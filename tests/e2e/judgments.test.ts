import { afterAll, test, expect } from "bun:test";
import { defineFile } from "./support/run.ts";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import type { DecisionQuestion, DecisionRung, QuestionAnswer, QuestionDefinitionInput, ArtifactAskOutcome, PairedReading, ProviderPin, QuestionCriteria, TypedDecision } from "@oneiron/client/facade-types";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";
import type { PairedActor } from "./support/engine.ts";
import { createHash } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3";

/**
 * Typed judgments and telemetry (OF-092/093/105/106/259/260/265/403/493/506/508/516).
 *
 * Binding readback: HEAD d87313d7b261258435d5a202005367540be19608;
 * origin/main 1aec7a3c94647f7f2cb012aaa9e4e3c2ff3d7cd3 has no changes to the
 * inspected SDK, server API, decision configuration/host or CLI files.
 * Read packages/oneiron-client/src/{facade,facade-types}.ts, the public
 * Oneiron SDK, server OpenAPI assembly, api/{facade,saved_query}.rs,
 * api/facade/graph_ask_doors.rs, config/models/{decisions,decision_read}.rs,
 * decision_host.rs and cli.rs. Runtime OpenAPI is diagnostic, not an oracle.
 *
 * G01: keep a whole scenario BLOCKED when a required typed call is missing.
 * Available verdict/graph/question calls are not being called absent. They
 * cannot substitute for the missing setup, admission or observation below.
 * No generic facade cast, execute_code, vault.batch body, private storage or
 * Rust oracle is used to manufacture the missing behavior. In particular,
 * saved_query_oracle.rs supplies invariant ideas only, not its Vault seeding.
 *
 * Canon homes are ARCH-0076 #ask/#record/#escalation-doors-built and
 * #escalation-slot-divergence; ARCH-0036 #model-line; ARCH-0037 #storage;
 * ARCH-0004 #rrf-pipeline; ARCH-0003 #learning; ARCH-0040
 * #mcp-actor-ceilings/#memory-board-source-trust; ARCH-0078 #contract.
 * Source pins and registry coverage are in the shared suite-plan manifest.
 *
 * fixtures/judgments/manifest.json pins seven independently authored input
 * sets. The shared preflight loads them even though these registrations are
 * TODOs. Their aliases are not entity IDs or seeds: future flows resolve
 * them from public creation receipts. Fixture admission vectors are never
 * presented as actual server receipts. No expected value comes from code
 * under test. No new public URL or verb name is invented for a missing door.
 *
 * Activation uses loadFixtures, ScriptedProviders and EngineFixture, fresh
 * authenticated processes and only the documented public calls. No helper
 * replacement is needed. One slot; normal harness deadlines; no sleeps,
 * private clock, mutation retry, model download or changed engine constant.
 */
const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

interface judg01Fixture {
  question: { text: string; contract: { kind: "noul" } };
  units: Record<string, string>;
  dial: { first: DecisionRung; ceiling: DecisionRung; band: { low: number; high: number } };
  confidenceCases: { id: string; p: number; higherP?: number; answer: boolean }[];
}
interface judg01Tools {
  tools: { name: string; inputSchema: { properties: { schema_version: { const: string } } } }[];
}
function judg01SystemOne(id: string, p: number): ProviderStep {
  return { id, origin: "judg01-system-one", role: "system_one", purpose: id,
    request: { method: "POST", path: "/v1/systemone", model: "fixture-precision-p1",
      fields: { questions: { decision: { type: "noul" } } } },
    response: { kind: "json", body: { model: "fixture-precision-p1",
      answers: { decision: { type: "noul", noul: p } }, usage: { input_tokens: 10, output_tokens: 5 } } } };
}
function judg01Big(id: string, text: string): ProviderStep {
  return { id, origin: "judg01-big", role: "checker", purpose: id,
    request: { method: "POST", path: "/v1/chat/completions", model: "fixture-big",
      fields: { stream: false }, system: "You answer one typed question about the state you are given." },
    response: openaiText(id, "fixture-big", text, { inputTokens: 20, outputTokens: 4 }) };
}
function judg01Sorted(rows: QuestionAnswer[]): QuestionAnswer[] {
  return [...rows].sort((a, b) => {
    const left = a.kind === "graph" ? a.claim : a.artifact;
    const right = b.kind === "graph" ? b.claim : b.artifact;
    return left.localeCompare(right);
  });
}
function judg01Rows(reply: FacadeResult<"vault.questions.answers">): QuestionAnswer[] {
  return judg01Sorted(Array.isArray(reply) ? reply : reply.answers);
}
async function judg01Refusal<V extends FacadeVerb>(
  engine: EngineFixture, caller: PublicHttpClient, principal: string, verb: V,
  input: FacadeInput<V>, status: number, code: string,
): Promise<string> {
  let failure: unknown;
  try { await caller.call(verb, input); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`Expected ${verb} public refusal`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  const receiptRef = failure.error?.receiptRef;
  expect(receiptRef).toEqual(expect.stringMatching(/^call:[a-f0-9]{32}$/));
  if (typeof receiptRef !== "string") throw new Error(`Missing ${verb} refusal receipt`);
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(() => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `judg01 ${verb} refusal receipt` });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport: "http_facade",
    verb: `v1/core/facade/${verb}`, actor_ref: principal,
    outcome: { refused: { code } } });
  return receiptRef;
}
async function judg01Question(
  engine: EngineFixture, facts: judg01Fixture, units: string[], first: DecisionRung, ceiling: DecisionRung,
): Promise<DecisionQuestion> {
  const definition: QuestionDefinitionInput = {
    question: { ...facts.question, class: "judgment", accept_type: false },
    adapter: "graph", units, recipe: "judg01-fixture", profile: "judg01-fixture",
    dial: { first, ceiling, band: facts.dial.band }, activation: "standing",
    refresh: { on_arrival: false }, delivery: "judg01-fixture", learning: false, deadline_ms: 2_000,
  };
  const created = await engine.client.call("vault.questions.create", { definition });
  const question = created.definition.question;
  expect(question.version).toBe(1);
  expect(await engine.client.call("vault.questions.read", { id: question.id })).toEqual(created);
  return question;
}
async function judg01Enforce(engine: EngineFixture, facts: judg01Fixture, question: DecisionQuestion) {
  const key = { question, reversibility: "reversible_read" as const };
  expect(await engine.client.call("vault.decisions.bands.read", { ...key, seed: facts.dial.band }))
    .toEqual({ band: facts.dial.band, version: 0, mode: "shadow" });
  expect(await engine.client.call("vault.decisions.bands.learn", { ...key, band: facts.dial.band, version: 1 }))
    .toEqual({ band: facts.dial.band, version: 1, mode: "shadow" });
  expect(await engine.client.call("vault.decisions.bands.read", { ...key, seed: facts.dial.band }))
    .toEqual({ band: facts.dial.band, version: 1, mode: "shadow" });
  await engine.client.call("vault.decisions.bands.enforce", key);
  expect(await engine.client.call("vault.decisions.bands.read", { ...key, seed: { low: 0.2, high: 0.8 } }))
    .toEqual({ band: facts.dial.band, version: 1, mode: "enforce" });
}
async function judg01McpRefresh(engine: EngineFixture, tools: judg01Tools, id: string) {
  const verb = "vault.questions.refresh";
  const tool = tools.tools.find(row => row.name === verb);
  if (!tool) throw new Error(`Required public MCP tool missing: ${verb}`);
  const input: FacadeInput<typeof verb> = { id };
  const reply = await engine.mcp.callTool(verb, {
    schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:judg01", purpose: "typed decision ladder parity" },
    arguments: { spec: input },
  }) as { isError: boolean; structuredContent: { output: FacadeResult<typeof verb>; meta: { end: string } } };
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent.meta.end).toBe("Complete");
  return reply.structuredContent.output;
}

/* JUDGMENTS-01 — Typed decision ladder fails closed should work.
 * Fixture: judgments-ladder (ladder.json). OF-493.
 * A text first read uses the public System One binding; the served Local
 * binding is image-only, so this is partial local-text coverage. HTTP and
 * tool-first MCP prove learned-band decisions, legal intermediate skips,
 * a bounded ceiling, attributable receipts and fail-closed provider failure.
 * Owner-only band doors refuse an ordinary agent with readable call receipts.
 * Selected Local absent MUST refuse without calling higher; learned bands
 * MUST survive restart. Both promises remain assertions despite known defects.
 * No model answer changes the captured policy, credential ceiling or withheld
 * source reach. A queued responsible-role ask is a request, never a grant.
 */
suite.test(test, "JUDGMENTS-01", "Learned decision bands bound HTTP/MCP answers, refuse an absent selected first rung, and survive restart", async () => {
  const facts = await (await loadFixtures()).readJson<judg01Fixture>("judgments-ladder");
  const steps: ProviderStep[] = [];
  for (const transport of ["http", "mcp"]) {
    for (const row of facts.confidenceCases) {
      steps.push(judg01SystemOne(`judg01-${transport}-${row.id}`, row.p));
      if (row.higherP !== undefined) steps.push(judg01Big(`judg01-${transport}-step-up`, JSON.stringify({ answer: row.answer, probability: row.higherP })));
    }
  }
  steps.push(judg01SystemOne("judg01-ceiling", 0.5), judg01SystemOne("judg01-role", 0.5),
    judg01Big("judg01-role-abstain", '{"answer":null,"probability":0.5}'));
  const failedFirst = judg01SystemOne("judg01-present-provider-503", 0.5);
  steps.push({ ...failedFirst, response: { kind: "json", status: 503,
    body: { error: { type: "server_error", message: "fixture unavailable" } } } });
  const providers = await ScriptedProviders.start({ id: "JUDGMENTS-01", steps });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "JUDGMENTS-01", profile, serverConfig: `
[models.providers.judg01]
kind = "local-openai-compat"
base_url = "${providers.urls["judg01-big"]}"
revision = "e2e-v1"
request_compression = false
timeout_secs = 1
[models.roles.checker]
model = "judg01:fixture-big"
[models.decisions.big]
role = "checker"
version = "b1"
wording = "You answer one typed question about the state you are given."
reply = "json"
[models.decisions.system_one]
endpoint = "${providers.urls["judg01-system-one"]}/v1/systemone"
# The loopback fixture accepts a non-secret token: the harness-owned TZ=UTC.
key_env = "TZ"
model = "fixture-precision"
version = "p1"
remote_opt_in = true
[models.dreamer]
enabled = false
` });
    const owner = engine.client;
    const agentId = "00000000000000000000000000aa0101";
    await owner.call("vault.agents.create", { agent_def_ref: agentId,
      definition: { agent_id: "judg01-unprivileged", display_name: "Judgment band observer",
        desc: "Inert decision-band refusal control", version: "1" } });
    expect((await owner.call("vault.get", { entity_ref: agentId })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: agentId, actorClass: "agent" });
    expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentId, actor_class: "agent" });
    const withheldText = "Only the source owner may use this separate parcel unit.";
    const withheld = await owner.call("vault.notes.create", { kind: "reflection", markdown: withheldText });
    expect((await owner.call("vault.notes.read", { note_ref: withheld.id_hex,
      reason: "Verify the independent withheld-source control" })).value?.markdown).toBe(withheldText);
    const policy = await owner.call("vault.gate.policy.get", {});
    const ceiling = await agent.client.call("vault.scope.ceiling", {});
    const withheldBefore = (await agent.client.call("vault.get", { entity_ref: withheld.id_hex })).value;
    expect(withheldBefore).toBeNull();
    const sourceIds: string[] = [];
    for (const alias of ["not-ready", "uncertain", "ready"]) {
      const text = facts.units[alias];
      if (text === undefined) throw new Error(`Missing judgments-ladder unit ${alias}`);
      const note = await owner.call("vault.notes.create", { kind: "research", markdown: text });
      expect((await owner.call("vault.notes.read", { note_ref: note.id_hex })).value?.markdown).toBe(text);
      sourceIds.push(note.id_hex);
    }
    const checkAuthority = async () => {
      expect((await owner.call("vault.gate.policy.get", {})).manifests).toEqual(policy.manifests);
      expect(await agent.client.call("vault.scope.ceiling", {})).toEqual(ceiling);
      expect((await agent.client.call("vault.get", { entity_ref: withheld.id_hex })).value).toEqual(withheldBefore);
      expect(JSON.stringify(providers.seenFixtureCalls.map(call => call.body))).not.toContain(withheldText);
    };
    const httpQuestion = await judg01Question(engine, facts, sourceIds, "system_one", "big");
    await judg01Enforce(engine, facts, httpQuestion);
    const key = { question: httpQuestion, reversibility: "reversible_read" as const };
    const refusals = [];
    refusals.push(await judg01Refusal(engine, agent.client, agentId, "vault.decisions.bands.read", { ...key, seed: facts.dial.band }, 403, "FORBIDDEN"));
    refusals.push(await judg01Refusal(engine, agent.client, agentId, "vault.decisions.bands.learn", { ...key, band: facts.dial.band, version: 2 }, 403, "FORBIDDEN"));
    refusals.push(await judg01Refusal(engine, agent.client, agentId, "vault.decisions.bands.enforce", key, 403, "FORBIDDEN"));
    await judg01Refusal(engine, owner, engine.pairedActor.principalRef, "vault.decisions.bands.learn", { ...key, band: facts.dial.band, version: 0 }, 400, "BAD_REQUEST");
    expect(await owner.call("vault.decisions.bands.read", { ...key, seed: facts.dial.band }))
      .toEqual({ band: facts.dial.band, version: 1, mode: "enforce" });
    const snapshots: { question: DecisionQuestion; rows: QuestionAnswer[] }[] = [];
    for (const transport of ["http", "mcp"] as const) {
      const question = transport === "http" ? httpQuestion : await judg01Question(engine, facts, sourceIds, "system_one", "big");
      if (transport === "mcp") await judg01Enforce(engine, facts, question);
      let answered: FacadeResult<"vault.questions.refresh">;
      if (transport === "http") answered = await owner.call("vault.questions.refresh", { id: question.id });
      else {
        await engine.mcp.initialize();
        const tools = await engine.mcp.listTools() as judg01Tools;
        answered = await judg01McpRefresh(engine, tools, question.id);
      }
      expect(answered).toHaveLength(3);
      for (let index = 0; index < facts.confidenceCases.length; index++) {
        const expected = facts.confidenceCases[index]!;
        const answer = answered.find(row => row.kind === "graph" && row.unit === sourceIds[index]);
        if (!answer || answer.kind !== "graph") throw new Error("Missing graph decision");
        expect(answer.decision.answer).toEqual({ kind: "noul", value: expected.answer });
        expect(answer.decision.probability).toBe(expected.higherP ?? expected.p);
        expect(answer.decision.receipt).toMatchObject({ question: question.id, question_version: 1,
          principal: engine.pairedActor.principalRef, band: facts.dial.band, band_version: 1 });
        expect(answer.decision.receipt.providers).toEqual([
          { rung: "system_one", model: "fixture-precision", version: "p1" },
          ...(expected.higherP === undefined ? [] : [{ rung: "big", model: "judg01/fixture-big@e2e-v1", version: "b1" }]),
        ]);
        expect(answer.decision.receipt.paired ?? []).toEqual([]);
        expect(answer.decision.receipt.evidence_versions?.some(pin => pin.id === answer.unit)).toBe(true);
        expect((await owner.call("vault.get", { entity_ref: answer.claim })).value?.kind).toBe("CLAIM");
      }
      const rows = judg01Rows(await owner.call("vault.questions.answers", { id: question.id }));
      expect(rows).toEqual(judg01Sorted(answered));
      snapshots.push({ question, rows });
      await checkAuthority();
    }
    const bounded = await judg01Question(engine, facts, [sourceIds[1]!], "system_one", "escalation");
    await judg01Enforce(engine, facts, bounded);
    const beforeBounded = providers.seenFixtureCalls.length;
    const boundedAnswers = await owner.call("vault.questions.refresh", { id: bounded.id });
    expect(boundedAnswers).toHaveLength(1);
    expect(boundedAnswers[0]).toMatchObject({ kind: "graph", decision: { answer: { kind: "abstain" }, human_ask: "provider_unavailable" } });
    expect(providers.seenFixtureCalls.slice(beforeBounded).map(call => call.origin)).toEqual(["judg01-system-one"]);
    expect(judg01Rows(await owner.call("vault.questions.answers", { id: bounded.id }))).toEqual(boundedAnswers);
    snapshots.push({ question: bounded, rows: boundedAnswers });
    await checkAuthority();
    const role = await judg01Question(engine, facts, [sourceIds[1]!], "system_one", "human");
    await judg01Enforce(engine, facts, role);
    const roleAnswers = await owner.call("vault.questions.refresh", { id: role.id });
    expect(roleAnswers).toHaveLength(1);
    const roleAnswer = roleAnswers[0];
    if (!roleAnswer || roleAnswer.kind !== "graph") throw new Error("Missing responsible-role decision");
    expect(roleAnswer.decision.answer).toEqual({ kind: "abstain" });
    expect(roleAnswer.decision.receipt.asked).toMatchObject({ role: "responsible", ceiling: "owner", act: "judgment" });
    const seq = roleAnswer.decision.receipt.asked?.seq;
    expect(typeof seq).toBe("number");
    const queued = (await owner.call("self.decisions.asks", {})).find(ask => ask.seq === seq);
    expect(queued).toMatchObject({ question: { id: role.id }, principal: engine.pairedActor.principalRef,
      to: { role: { role: "responsible", actor: engine.pairedActor.principalRef }, ceiling: "owner", act: "judgment" } });
    expect(queued?.answer).toBeFalsy();
    expect(judg01Rows(await owner.call("vault.questions.answers", { id: role.id }))).toEqual(roleAnswers);
    snapshots.push({ question: role, rows: roleAnswers });
    await checkAuthority();
    const failureQuestion = await judg01Question(engine, facts, [sourceIds[0]!], "system_one", "big");
    const beforeFailure = providers.seenFixtureCalls.length;
    await judg01Refusal(engine, owner, engine.pairedActor.principalRef, "vault.questions.refresh", { id: failureQuestion.id }, 400, "BAD_REQUEST");
    expect(providers.seenFixtureCalls.slice(beforeFailure).map(call => call.fixtureId)).toEqual(["judg01-present-provider-503"]);
    expect(judg01Rows(await owner.call("vault.questions.answers", { id: failureQuestion.id }))).toEqual([]);
    await checkAuthority();
    const absent = await judg01Question(engine, facts, [sourceIds[2]!], facts.dial.first, facts.dial.ceiling);
    expect(facts.dial.first).toBe("local");
    await owner.call("vault.questions.pause", { id: role.id, paused: true });
    expect(await owner.call("vault.questions.schedule", { id: role.id })).toMatchObject({ id: role.id, paused: true });
    await engine.restart();
    expect(await owner.call("vault.questions.schedule", { id: role.id })).toMatchObject({ id: role.id, paused: true });
    for (const { question, rows } of snapshots) {
      expect((await owner.call("vault.questions.read", { id: question.id }))?.definition.question).toEqual(question);
      expect(judg01Rows(await owner.call("vault.questions.answers", { id: question.id }))).toEqual(rows);
    }
    for (const receipt_ref of refusals) {
      expect(await owner.call("vault.receipts.get", { receipt_ref })).toMatchObject({
        receipt_ref, actor_ref: agentId, actor_class: "agent", outcome: { refused: { code: "FORBIDDEN" } },
      });
    }
    expect((await owner.call("self.decisions.asks", {})).find(ask => ask.seq === seq)).toEqual(queued);
    const learnedAfterRestart = await owner.call("vault.decisions.bands.read", { ...key, seed: { low: 0.2, high: 0.8 } });
    await checkAuthority();
    // Keep both known-defect observations: the first red must not hide the second.
    const beforeAbsent = providers.seenFixtureCalls.length;
    let absentFailure: unknown;
    try { await owner.call("vault.questions.refresh", { id: absent.id }); } catch (error) { absentFailure = error; }
    const absentAnswers = judg01Rows(await owner.call("vault.questions.answers", { id: absent.id }));
    const absentCalls = providers.seenFixtureCalls.slice(beforeAbsent);
    await engine.artifacts.json("judg01-promised-invariants.json", { learnedAfterRestart,
      selectedFirstAbsent: { providerCalls: absentCalls.map(call => ({ origin: call.origin, fixtureId: call.fixtureId })),
        answerCount: absentAnswers.length, status: absentFailure instanceof PublicHttpError ? absentFailure.reply.status : null,
        code: absentFailure instanceof PublicHttpError ? absentFailure.error?.code : null } });
    expect({ selectedFirstProviderCalls: absentCalls.length,
      selectedFirstRefused: absentFailure instanceof PublicHttpError && absentFailure.reply.status >= 400 && absentFailure.reply.status < 500,
      selectedFirstAnswerCount: absentAnswers.length, learnedAfterRestart }).toEqual({
      selectedFirstProviderCalls: 0, selectedFirstRefused: true, selectedFirstAnswerCount: 0,
      learnedAfterRestart: { band: facts.dial.band, version: 1, mode: "enforce" },
    });
  } finally {
    try { await engine?.close(); } finally { await providers.close(); }
  }
});

interface judg02Fixture {
  scenario: string;
  units: { "graph-note": string; "artifact-paragraph": string };
  question: { text: string; contract: { kind: string }; versions: { version: number; criteria: QuestionCriteria<string>; expectedAnswer?: boolean; expected?: string }[] };
  answeredQuestion: string;
  pairedQuestion: string;
  measuringPin: ProviderPin;
  validPair: PairedReading;
  invalidPairs: { id: string; mutation: string }[];
  expected: { absentPair: unknown[]; validPairPreserved: boolean; invalidPairMintsClaim: boolean; receiptScope: string; criteriaEditMintsVersion: boolean; oldReceiptChanges: boolean; artifactLanding: string; graphLanding: string };
}
const judg02Wording = "You answer one typed question about the state you are given.";
const judg02WireModel = "fixture-parity";
const judg02BigPin: ProviderPin = { rung: "big", model: "parity/fixture-parity@e2e-v1", version: "e2e-v1" };
const judg02RulePin: ProviderPin = { rung: "rule", model: "host-rules", version: "1" };
const judg02Pin: ProviderPin = { rung: "escalation", model: "fixture-house-read", version: "e1" };
const judg02Labels = { yes: "yes", no: "no", low: "low", middle: "middle", high: "high" };
const judg02DocxMedia = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
function judg02Step(id: string, response: ProviderStep["response"]): ProviderStep {
  return { id, origin: "parity", role: "checker", purpose: `judg02 big ${id}`,
    request: { method: "POST", path: "/v1/chat/completions", model: judg02WireModel,
      fields: { stream: false }, system: judg02Wording }, response };
}
async function judg02Error(action: () => Promise<unknown>, status: number, code: string): Promise<PublicHttpError> {
  try { await action(); } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(status);
    expect(error.error?.code).toBe(code);
    return error;
  }
  throw new Error(`Expected HTTP ${status} ${code}`);
}
async function judg02RefusalReceipt(engine: EngineFixture, error: PublicHttpError, verb: string,
  actorRef: string, actorClass: string, reader?: PublicHttpClient): Promise<string> {
  const receiptRef = error.error?.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error(`Facade refusal omitted its call receipt for ${verb}`);
  expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  expect(error.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(
    () => (reader ?? engine.client).call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `judg02 refusal receipt ${verb}` });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport: "http_facade",
    verb: `v1/core/facade/${verb}`, actor_ref: actorRef, actor_class: actorClass,
    outcome: { refused: { code: error.error?.code } } });
  return receiptRef;
}
function judg02NarrowAsk(value: FacadeResult<"vault.artifacts.ask">): ArtifactAskOutcome {
  if (typeof value === "object" && value !== null
    && ("details_on_device" in value || "questions_narrowed" in value))
    throw new Error("Artifact ask answered device-local; expected the direct outcome on loopback");
  return value as ArtifactAskOutcome;
}
function judg02AnswersList(reply: FacadeResult<"vault.questions.answers">): QuestionAnswer[] {
  return Array.isArray(reply) ? reply : reply.answers;
}
async function judg02ClaimIds(client: PublicHttpClient, subjectRef: string): Promise<string[]> {
  const listed = await client.call("vault.claims.list",
    { subject_ref: subjectRef, predicate: "judgment.answer", limit: 100 });
  return listed.value.map(row => row.claim_ref).sort();
}
function judg02Hex(bytes: readonly number[]): string {
  return bytes.map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function judg02EscapeXml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
const judg02CrcTable: number[] = (() => {
  const table: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table.push(c >>> 0);
  }
  return table;
})();
function judg02Crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = judg02CrcTable[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function judg02Zip(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const encoded = new TextEncoder();
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  let centralSize = 0;
  for (const file of files) {
    const name = encoded.encode(file.name);
    const head = new DataView(new ArrayBuffer(30));
    head.setUint32(0, 0x04034b50, true);
    head.setUint16(4, 20, true);
    head.setUint16(6, 0x0800, true);
    head.setUint16(8, 0, true);
    head.setUint16(10, 0, true);
    head.setUint16(12, 0x5821, true);
    head.setUint32(14, judg02Crc32(file.data), true);
    head.setUint32(18, file.data.length, true);
    head.setUint32(22, file.data.length, true);
    head.setUint16(26, name.length, true);
    head.setUint16(28, 0, true);
    const cen = new DataView(new ArrayBuffer(46));
    cen.setUint32(0, 0x02014b50, true);
    cen.setUint16(4, 20, true);
    cen.setUint16(6, 20, true);
    cen.setUint16(8, 0x0800, true);
    cen.setUint16(10, 0, true);
    cen.setUint16(12, 0, true);
    cen.setUint16(14, 0x5821, true);
    cen.setUint32(16, judg02Crc32(file.data), true);
    cen.setUint32(20, file.data.length, true);
    cen.setUint32(24, file.data.length, true);
    cen.setUint16(28, name.length, true);
    cen.setUint16(30, 0, true);
    cen.setUint16(32, 0, true);
    cen.setUint16(34, 0, true);
    cen.setUint16(36, 0, true);
    cen.setUint32(38, 0, true);
    cen.setUint32(42, offset, true);
    chunks.push(new Uint8Array(head.buffer), name, file.data);
    central.push(new Uint8Array(cen.buffer), name);
    offset += 30 + name.length + file.data.length;
    centralSize += 46 + name.length;
  }
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(4, 0, true);
  end.setUint16(6, 0, true);
  end.setUint16(8, files.length, true);
  end.setUint16(10, files.length, true);
  end.setUint32(12, centralSize, true);
  end.setUint32(16, offset, true);
  end.setUint16(20, 0, true);
  const parts = [...chunks, ...central, new Uint8Array(end.buffer)];
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function judg02Docx(text: string): string {
  const encoded = new TextEncoder();
  const body = judg02EscapeXml(text);
  const files = [
    { name: "[Content_Types].xml", data: encoded.encode(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>`) },
    { name: "_rels/.rels", data: encoded.encode(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`) },
    { name: "word/_rels/document.xml.rels", data: encoded.encode(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`) },
    { name: "word/document.xml", data: encoded.encode(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t xml:space="preserve">${body}</w:t></w:r></w:p></w:body></w:document>`) },
    { name: "word/styles.xml", data: encoded.encode(
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>`) },
  ];
  return Buffer.from(judg02Zip(files)).toString("base64");
}
function judg02GraphDef(text: string, unit: string, criteria: QuestionCriteria<string>): QuestionDefinitionInput {
  return { question: { text, class: "judgment", contract: { kind: "noul" }, accept_type: false },
    adapter: "graph", units: [unit], recipe: "fixture", profile: "fixture",
    dial: { first: "rule", ceiling: "big", band: { low: 0.35, high: 0.65 } },
    activation: "standing", refresh: { on_arrival: false }, delivery: "fixture",
    learning: false, criteria };
}
function judg02ArtifactDef(text: string, artifact: string, blocks: string[],
  criteria: QuestionCriteria<string>): QuestionDefinitionInput {
  return { question: { text, class: "judgment", contract: { kind: "noul" }, accept_type: false },
    adapter: "artifact", units: [], recipe: "fixture", profile: "fixture",
    dial: { first: "rule", ceiling: "big", band: { low: 0.35, high: 0.65 } },
    activation: "standing", refresh: { on_arrival: false }, delivery: "fixture",
    learning: false, criteria,
    artifacts: [{ artifact, selection: { kind: "paragraphs", blocks,
      author: "fixture", labels: judg02Labels } }] };
}
function judg02Decision(question: string, questionVersion: number, principal: string,
  paired: PairedReading[]): TypedDecision {
  return { answer: { kind: "noul", value: true }, probability: 0.9, evidence: [], in_band: false,
    receipt: { question, question_version: questionVersion, principal, providers: [judg02Pin],
      band: { low: 0.35, high: 0.65 }, band_version: 0, evidence_versions: [], paired } };
}

/* JUDGMENTS-02 — Graph and artifact question parity should work.
 * Fixture: judgments-parity (parity.json). OF-506/508.
 * Partial: the same fixture Noul Qv1 over a graph NOTE and a DOCX paragraph
 * lands a graph claim and a kept artifact judgment with the same question id,
 * while the one-off proposal sits held and inert first. Paired-output
 * admission on BOTH adapters preserves one valid reading and refuses the five
 * fixture vectors before any claim or proposal; the claim inventory is
 * compared around every invalid vector. Criteria v1/v2 version on graph
 * and artifact standing questions through edit/refresh, with v1 receipts
 * pinned; C2 yields no Noul answer — the v2
 * artifact refresh abstains for its missing required input and v1 bytes stay
 * settled beside the v2 ask history. Ladder answers carry the local Rule
 * abstention pin ahead of Big; admitted answers keep their submitted pin.
 * Read-only refusals on the decision verbs carry receipts; another actor
 * reads those receipts as null. A refused provider fails the graph ask
 * openly; garbage replies abstain without fabricating an answer. Everything
 * is re-read after a restart. Seven FIFO Big calls on one origin, one
 * engine, no standing steps.
 * Unproved: answered decisions inside a HELD proposal (no typed held-decision
 * read on the proposals surface) and one-off artifact criteria (the ask takes
 * none); artifact receipts are read after Keep and criteria version on
 * standing questions instead. Scripted answers prove mechanics, never that a
 * model inferred C2.
 */
suite.test(test, "JUDGMENTS-02", "Graph and artifact v1 parity with paired admission on both adapters, criteria versioning, and refusal and restart readback", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<judg02Fixture>("judgments-parity");
  expect(fixture.scenario).toBe("JUDGMENTS-02");
  const graphText = fixture.units["graph-note"];
  const paragraphText = fixture.units["artifact-paragraph"];
  expect(graphText).toBe("Parcel R17 is ready.");
  expect(paragraphText).toBe(graphText);
  expect(fixture.question.text).toBe("Is the parcel ready?");
  expect(fixture.question.contract).toEqual({ kind: "noul" });
  const v1 = fixture.question.versions.find(row => row.version === 1);
  const v2 = fixture.question.versions.find(row => row.version === 2);
  if (!v1 || !v2) throw new Error("Parity fixture needs criteria versions 1 and 2");
  expect(v1.criteria.yes_if_all).toHaveLength(1);
  expect(v1.expectedAnswer).toBe(true);
  expect(v2.criteria.yes_if_all).toHaveLength(2);
  expect(v2.criteria.not_a_reason_to_say_no).toEqual([]);
  expect(v2.expected).toBe("abstain for missing required input, not a negative label");
  expect(fixture.measuringPin).toEqual(judg02Pin);
  expect(fixture.validPair).toEqual({ provider: judg02Pin, question: fixture.pairedQuestion,
    question_version: 1, probability: 0.82 });
  expect(fixture.invalidPairs.map(row => row.id).sort()).toEqual(
    ["duplicate-provider", "out-of-range", "self-question", "wrong-provider", "zero-version"]);
  expect(fixture.expected.artifactLanding).toContain("source head unchanged");
  expect(fixture.expected.graphLanding).toContain("answer claim");
  const questionV1: DecisionQuestion = { id: fixture.answeredQuestion, version: 1,
    text: fixture.question.text, class: "judgment", contract: { kind: "noul" }, accept_type: false };
  const providers = await ScriptedProviders.start({ id: "JUDGMENTS-02", steps: [
    judg02Step("judg02-graph-v1", openaiText("judg02-graph-v1", judg02WireModel,
      `{"answer":true,"probability":0.9}`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-artifact-v1", openaiText("judg02-artifact-v1", judg02WireModel,
      `{"answer":true,"probability":0.9}`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-standing-artifact-v1", openaiText("judg02-standing-artifact-v1", judg02WireModel,
      `{"answer":true,"probability":0.9}`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-standing-artifact-v2", openaiText("judg02-standing-artifact-v2", judg02WireModel,
      `{}`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-graph-v2-abstain", openaiText("judg02-graph-v2-abstain", judg02WireModel,
      `{}`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-artifact-garbage", openaiText("judg02-artifact-garbage", judg02WireModel,
      `this is not JSON at all`, { inputTokens: 20, outputTokens: 4 })),
    judg02Step("judg02-graph-auth-fail", { kind: "json", status: 401,
      body: { error: { type: "invalid_key", message: "fixture provider refused the key" } } }),
  ] });
  const engine = await EngineFixture.start({ id: "JUDGMENTS-02", profile, serverConfig: `
[models.providers.parity]
kind = "local-openai-compat"
base_url = "${providers.urls.parity}"
revision = "e2e-v1"
request_compression = false
timeout_secs = 5
[models.roles.checker]
model = "parity:${judg02WireModel}"
[models.decisions.big]
role = "checker"
version = "e2e-v1"
wording = "${judg02Wording}"
reply = "json"
[models.dreamer]
enabled = false
` });
  try {
  const owner = engine.client;
  const ownerRef = engine.pairedActor.principalRef;
  const note = await owner.call("vault.notes.create", { kind: "research", markdown: graphText });
  const noteRef = note.id_hex;
  const noteRead = await owner.call("vault.get", { entity_ref: noteRef });
  expect(noteRead.value).not.toBeNull();
  expect(noteRead.value?.id_hex).toBe(note.id_hex);
  const withheld = await owner.call("vault.notes.create", { kind: "reflection", markdown: "Parcel R17 is not ready." });
  const withheldRef = withheld.id_hex;
  const withheldRead = await owner.call("vault.notes.read", { note_ref: withheldRef, reason: "judg02 withheld control setup" });
  expect(withheldRead.value).not.toBeNull();
  expect(JSON.stringify(withheldRead.value)).toContain("Parcel R17 is not ready.");
  const roRef = "0000000000000000000000000000aa02a1";
  const peerRef = "0000000000000000000000000000aa02a2";
  await owner.call("vault.agents.create", { agent_def_ref: roRef,
    definition: { agent_id: "judg02-readonly", desc: "Inert read-only refusal principal", version: "1" } });
  await owner.call("vault.agents.create", { agent_def_ref: peerRef,
    definition: { agent_id: "judg02-peer", desc: "Inert peer principal for withheld and receipt reads", version: "1" } });
  expect((await owner.call("vault.get", { entity_ref: roRef })).value?.kind).toBe("AGENT_DEF");
  expect((await owner.call("vault.get", { entity_ref: peerRef })).value?.kind).toBe("AGENT_DEF");
  const roAgent: PairedActor = await engine.pairActor({ principalRef: roRef, actorClass: "agent", scope: ["core:read"] });
  const peerAgent: PairedActor = await engine.pairActor({ principalRef: peerRef, actorClass: "agent", scope: ["core:read", "core:write"] });
  expect(await roAgent.client.call("self.actor", {})).toMatchObject({ actor_ref: roRef, actor_class: "agent" });
  expect(await peerAgent.client.call("self.actor", {})).toMatchObject({ actor_ref: peerRef, actor_class: "agent" });
  expect((await roAgent.client.call("vault.get", { entity_ref: noteRef })).value?.id_hex).toBe(note.id_hex);
  expect((await peerAgent.client.call("vault.get", { entity_ref: withheldRef })).value).toBeNull();
  expect((await roAgent.client.call("vault.get", { entity_ref: withheldRef })).value).toBeNull();
  const docxBase64 = judg02Docx(paragraphText);
  const created = await owner.call("vault.artifacts.create", { name: "judg02-parcel",
    media_type: judg02DocxMedia, content_base64: docxBase64 });
  if (!created) throw new Error("Parity artifact was not created");
  const artifactRef = created.artifact_id;
  const view1 = await owner.call("vault.artifacts.view", { artifact_ref: artifactRef });
  expect(view1?.head).toBe(1);
  expect(view1?.versions).toHaveLength(1);
  expect(view1?.name).toBe("judg02-parcel");
  expect((await owner.call("vault.artifacts.read", { artifact_ref: artifactRef, version: 1 }))?.content_base64).toBe(docxBase64);
  expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
  const imported = await owner.call("vault.artifacts.body.import", { artifact_ref: artifactRef });
  expect(imported.kind).toBe("docx");
  const bodyRead = await owner.call("vault.artifacts.body.read", { artifact_ref: artifactRef });
  if (bodyRead.format !== "docx") throw new Error("Parity live body is not docx");
  const block = bodyRead.body.blocks.find(row => row.text === paragraphText);
  if (!block) throw new Error("Parity paragraph block not found in the live body");
  const unitsRead = await owner.call("vault.artifacts.units", { artifact_ref: artifactRef });
  if (unitsRead.status !== "supported") throw new Error("Parity artifact reports no unit adapter");
  expect(unitsRead.units.some(row => row.quote?.includes(paragraphText))).toBe(true);
  const noteBaseline = (await owner.call("vault.get", { entity_ref: noteRef })).value;
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([]);
  const askV1Input: FacadeInput<"vault.graph.ask"> = { question: questionV1, units: [noteRef],
    criteria: v1.criteria, ceiling: "big", unit_deadline_ms: 2000 };
  const artifactAskV1: FacadeInput<"vault.artifacts.ask"> = { artifact_ref: artifactRef,
    run_ref: "judg02-oneoff-v1", question: questionV1,
    units: { kind: "paragraphs", blocks: [block.id], author: "fixture", labels: judg02Labels },
    unit_budget_ms: 2000, deadline_ms: 8000 };
  const ownerDecision = judg02Decision(questionV1.id, 1, ownerRef, [fixture.validPair]);
  const refusalRefs: string[] = [];
  const roAskRefusal = await judg02Error(() => roAgent.client.call("vault.graph.ask", askV1Input), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roAskRefusal, "vault.graph.ask", roRef, "agent", roAgent.client));
  const roAdmitRefusal = await judg02Error(() => roAgent.client.call("vault.graph.admit",
    { question: questionV1, unit: noteRef, decision: ownerDecision }), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roAdmitRefusal, "vault.graph.admit", roRef, "agent"));
  const roArtifactAskRefusal = await judg02Error(() => roAgent.client.call("vault.artifacts.ask", artifactAskV1), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roArtifactAskRefusal, "vault.artifacts.ask", roRef, "agent"));
  const roArtifactAdmitRefusal = await judg02Error(() => roAgent.client.call("vault.artifacts.admit",
    { ask: { ...artifactAskV1, run_ref: "judg02-refused-admit" }, decisions: [ownerDecision] }), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roArtifactAdmitRefusal, "vault.artifacts.admit", roRef, "agent"));
  const roCreateRefusal = await judg02Error(() => roAgent.client.call("vault.questions.create",
    { definition: judg02GraphDef(fixture.question.text, noteRef, v1.criteria) }), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roCreateRefusal, "vault.questions.create", roRef, "agent"));
  const roStandingAdmitRefusal = await judg02Error(() => roAgent.client.call("vault.questions.admit",
    { id: note.id_hex, expected_version: 1, input: { unit: noteRef, evidence: [] },
      source_frontier: Array(32).fill(0), decision: ownerDecision }), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roStandingAdmitRefusal, "vault.questions.admit", roRef, "agent"));
  const roRefreshRefusal = await judg02Error(() => roAgent.client.call("vault.questions.refresh", { id: note.id_hex }), 403, "FORBIDDEN");
  refusalRefs.push(await judg02RefusalReceipt(engine, roRefreshRefusal, "vault.questions.refresh", roRef, "agent"));
  expect(new Set(refusalRefs).size).toBe(refusalRefs.length);
  expect(providers.seenFixtureCalls).toHaveLength(0);
  expect((await owner.call("vault.get", { entity_ref: noteRef })).value).toEqual(noteBaseline);
  const peerWithheld = await peerAgent.client.call("vault.graph.admit",
    { question: questionV1, unit: withheldRef, decision: judg02Decision(questionV1.id, 1, peerRef, []) });
  expect(peerWithheld).toEqual({ state: "done", answers: [], abstained: [], declined: [] });
  expect(JSON.stringify(peerWithheld)).not.toContain(withheld.id_hex);
  const peerNote = await peerAgent.client.call("vault.graph.admit",
    { question: questionV1, unit: noteRef, decision: judg02Decision(questionV1.id, 1, peerRef, []) });
  if (peerNote.state !== "done") throw new Error("Peer admission on the readable note failed");
  expect(peerNote.answers).toHaveLength(1);
  const peerAnswer = peerNote.answers[0]!;
  expect(peerAnswer.decision.receipt.principal).toBe(peerRef);
  expect(peerAnswer.decision.receipt.providers).toEqual([judg02Pin]);
  expect((await peerAgent.client.call("vault.get", { entity_ref: peerAnswer.claim })).value?.id_hex).toBe(peerAnswer.claim);
  const claimsAfterPeer = await judg02ClaimIds(owner, noteRef);
  expect(providers.seenFixtureCalls).toHaveLength(0);
  const graphV1 = await owner.call("vault.graph.ask", askV1Input);
  if (graphV1.state !== "done") throw new Error("Graph v1 ask failed");
  expect(graphV1.abstained).toEqual([]);
  expect(graphV1.declined).toEqual([]);
  expect(graphV1.answers).toHaveLength(1);
  const graphAnswer = graphV1.answers[0]!;
  expect(graphAnswer.unit).toBe(noteRef);
  expect(graphAnswer.decision.answer).toEqual({ kind: "noul", value: true });
  expect(graphAnswer.decision.probability).toBe(0.9);
  expect(graphAnswer.decision.receipt.question).toBe(questionV1.id);
  expect(graphAnswer.decision.receipt.question_version).toBe(1);
  expect(graphAnswer.decision.receipt.principal).toBe(ownerRef);
  expect(graphAnswer.decision.receipt.providers).toEqual([judg02RulePin, judg02BigPin]);
  expect(graphAnswer.decision.receipt.paired ?? []).toEqual([]);
  expect(graphAnswer.decision.evidence).toContain(noteRef);
  expect(graphAnswer.decision.receipt.evidence_versions?.[0]?.id).toBe(noteRef);
  expect((await owner.call("vault.get", { entity_ref: graphAnswer.claim })).value?.id_hex).toBe(graphAnswer.claim);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsAfterPeer, graphAnswer.claim].sort());
  const artifactV1 = judg02NarrowAsk(await owner.call("vault.artifacts.ask", artifactAskV1));
  if (!artifactV1.proposed) throw new Error("Artifact v1 ask held no proposal");
  expect(artifactV1.abstained).toEqual([]);
  expect(artifactV1.refused).toEqual([]);
  expect(artifactV1.proposed.base_version).toBe(1);
  expect(artifactV1.proposed.retained_by).toBe(ownerRef);
  const oneOffRef = artifactV1.proposed.proposal_ref;
  expect((await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).map(row => row.proposal_ref)).toEqual([oneOffRef]);
  expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(1);
  expect((await owner.call("vault.artifacts.read", { artifact_ref: artifactRef, version: 1 }))?.content_base64).toBe(docxBase64);
  const keptOneOff = await owner.call("vault.artifacts.keep", { artifact_ref: artifactRef, proposal_ref: oneOffRef });
  expect(keptOneOff.version.version).toBe(2);
  expect(keptOneOff.stranded).toBe(false);
  expect(keptOneOff.review?.paragraph_judgments).toHaveLength(1);
  const judgmentOneOff = keptOneOff.review!.paragraph_judgments[0]!;
  expect(judgmentOneOff.block).toBe(block.id);
  expect(judgmentOneOff.decision.answer).toEqual({ kind: "noul", value: true });
  expect(judgmentOneOff.decision.probability).toBe(0.9);
  expect(judgmentOneOff.decision.receipt.question).toBe(questionV1.id);
  expect(judgmentOneOff.decision.receipt.question_version).toBe(1);
  expect(judgmentOneOff.decision.receipt.principal).toBe(ownerRef);
  expect(judgmentOneOff.decision.receipt.providers).toEqual([judg02RulePin, judg02BigPin]);
  expect(judgmentOneOff.decision.receipt.paired ?? []).toEqual([]);
  expect(judgmentOneOff.author).toBe("fixture");
  expect(judgmentOneOff.labels).toEqual(judg02Labels);
  expect(judgmentOneOff.comment.split(": ")[1]).toBe("yes");
  expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
  const view2 = await owner.call("vault.artifacts.view", { artifact_ref: artifactRef });
  expect(view2?.head).toBe(2);
  expect(view2?.versions).toHaveLength(2);
  const exportOneOff = (await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 2 }))?.content_base64;
  expect(typeof exportOneOff).toBe("string");
  const standing = await owner.call("vault.questions.create",
    { definition: judg02GraphDef(fixture.question.text, noteRef, v1.criteria) });
  const standingId = standing.definition.question.id;
  expect(standing.principal).toBe(ownerRef);
  expect(standing.definition.adapter).toBe("graph");
  const standingRead = await owner.call("vault.questions.read", { id: standingId });
  expect(standingRead?.definition.question.version).toBe(1);
  expect(standingRead?.definition.criteria).toEqual(v1.criteria);
  expect(await roAgent.client.call("vault.questions.read", { id: standingId })).toBeNull();
  expect(await peerAgent.client.call("vault.questions.read", { id: standingId })).toBeNull();
  const preparedV1 = await owner.call("vault.questions.prepare",
    { id: standingId, expected_version: 1, input: { unit: noteRef, evidence: [] } });
  expect(preparedV1.question.id).toBe(standingId);
  expect(preparedV1.principal).toBe(ownerRef);
  expect(preparedV1.unit).toBe(noteRef);
  expect(preparedV1.sources[0]!.id).toBe(noteRef);
  expect(preparedV1.source_frontier).toHaveLength(32);
  const admittedV1Decision: TypedDecision = { ...judg02Decision(standingId, 1, ownerRef, [fixture.validPair]),
    receipt: { ...judg02Decision(standingId, 1, ownerRef, [fixture.validPair]).receipt,
      evidence_versions: preparedV1.sources.map(source => ({ id: source.id, body_hash: judg02Hex(source.hash) })) } };
  const claimsBeforeStanding = await judg02ClaimIds(owner, noteRef);
  const admittedV1 = await owner.call("vault.questions.admit", { id: standingId, expected_version: 1,
    input: { unit: noteRef, evidence: [] }, source_frontier: preparedV1.source_frontier, decision: admittedV1Decision });
  expect(admittedV1.unit).toBe(noteRef);
  expect(admittedV1.decision).toEqual(admittedV1Decision);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsBeforeStanding, admittedV1.claim].sort());
  const answersV1 = judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }));
  expect(answersV1).toEqual([{ ...admittedV1, kind: "graph" }]);
  const edited = await owner.call("vault.questions.edit", { id: standingId, expected_version: 1,
    definition: judg02GraphDef(fixture.question.text, noteRef, v2.criteria) });
  expect(edited.definition.criteria).toEqual(v2.criteria);
  const readV1 = await owner.call("vault.questions.read", { id: standingId, version: 1 });
  expect(readV1?.definition.criteria).toEqual(v1.criteria);
  expect(readV1?.definition.question.version).toBe(1);
  const readHead = await owner.call("vault.questions.read", { id: standingId });
  expect(readHead?.definition.criteria).toEqual(v2.criteria);
  expect(readHead?.definition.question.version).toBe(2);
  const preparedV2 = await owner.call("vault.questions.prepare",
    { id: standingId, expected_version: 2, input: { unit: noteRef, evidence: [] } });
  expect(preparedV2.source_frontier).toHaveLength(32);
  const duplicatePair = { ...fixture.validPair };
  const admittedV2Shape: TypedDecision = { ...judg02Decision(standingId, 2, ownerRef, [fixture.validPair, duplicatePair]),
    receipt: { ...judg02Decision(standingId, 2, ownerRef, [fixture.validPair, duplicatePair]).receipt,
      evidence_versions: preparedV2.sources.map(source => ({ id: source.id, body_hash: judg02Hex(source.hash) })) } };
  await judg02Error(() => owner.call("vault.questions.admit", { id: standingId, expected_version: 2,
    input: { unit: noteRef, evidence: [] }, source_frontier: preparedV2.source_frontier, decision: admittedV2Shape }), 400, "BAD_REQUEST");
  expect(judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }))).toEqual([{ ...admittedV1, kind: "graph" }]);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsBeforeStanding, admittedV1.claim].sort());
  await judg02Error(() => owner.call("vault.questions.admit", { id: standingId, expected_version: 1,
    input: { unit: noteRef, evidence: [] }, source_frontier: preparedV1.source_frontier, decision: admittedV1Decision }), 409, "INVALID_STATE");
  const tampered = [...preparedV2.source_frontier];
  tampered[0] = (tampered[0]! + 1) % 256;
  await judg02Error(() => owner.call("vault.questions.admit", { id: standingId, expected_version: 2,
    input: { unit: noteRef, evidence: [] }, source_frontier: tampered,
    decision: { ...admittedV2Shape, receipt: { ...admittedV2Shape.receipt, paired: [fixture.validPair] } } }), 409, "INVALID_STATE");
  expect(judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }))).toEqual([{ ...admittedV1, kind: "graph" }]);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsBeforeStanding, admittedV1.claim].sort());
  const claimsBeforeAdmit = await judg02ClaimIds(owner, noteRef);
  const graphAdmitted = await owner.call("vault.graph.admit",
    { question: questionV1, unit: noteRef, decision: ownerDecision });
  if (graphAdmitted.state !== "done") throw new Error("One-off graph admission failed");
  expect(graphAdmitted.answers).toHaveLength(1);
  const graphAdmittedAnswer = graphAdmitted.answers[0]!;
  expect(graphAdmittedAnswer.decision.receipt.paired).toEqual([fixture.validPair]);
  expect(graphAdmittedAnswer.decision.receipt.providers).toEqual([judg02Pin]);
  expect(graphAdmittedAnswer.decision.receipt.question).toBe(questionV1.id);
  expect(graphAdmittedAnswer.decision.receipt.principal).toBe(ownerRef);
  expect(graphAdmittedAnswer.decision.evidence[0]).toBe(noteRef);
  expect((await owner.call("vault.get", { entity_ref: graphAdmittedAnswer.claim })).value?.id_hex).toBe(graphAdmittedAnswer.claim);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsBeforeAdmit, graphAdmittedAnswer.claim].sort());
  const beforeInvalid = providers.seenFixtureCalls.length;
  const invalidPairs: { id: string; paired: PairedReading[] }[] = [
    { id: "duplicate-provider", paired: [fixture.validPair, { ...fixture.validPair }] },
    { id: "wrong-provider", paired: [{ provider: { rung: "escalation", model: "fixture-unmeasured", version: "e1" },
      question: fixture.validPair.question, question_version: 1, probability: 0.82 }] },
    { id: "self-question", paired: [{ ...fixture.validPair, question: questionV1.id }] },
    { id: "zero-version", paired: [{ ...fixture.validPair, question_version: 0 }] },
    { id: "out-of-range", paired: [{ ...fixture.validPair, probability: 1.1 }] },
  ];
  for (const vector of invalidPairs) {
    const claimsBeforeVector = await judg02ClaimIds(owner, noteRef);
    await judg02Error(() => owner.call("vault.graph.admit", { question: questionV1, unit: noteRef,
      decision: { ...ownerDecision, receipt: { ...ownerDecision.receipt, paired: vector.paired } } }), 400, "BAD_REQUEST");
    expect(await judg02ClaimIds(owner, noteRef)).toEqual(claimsBeforeVector);
    expect(providers.seenFixtureCalls).toHaveLength(beforeInvalid);
  }
  expect((await owner.call("vault.get", { entity_ref: noteRef })).value).toEqual(noteBaseline);
  await owner.call("vault.artifacts.body.import", { artifact_ref: artifactRef });
  const bodyReadHead2 = await owner.call("vault.artifacts.body.read", { artifact_ref: artifactRef });
  if (bodyReadHead2.format !== "docx") throw new Error("Parity live body is not docx at head 2");
  const blockHead2 = bodyReadHead2.body.blocks.find(row => row.text === paragraphText);
  if (!blockHead2) throw new Error("Parity paragraph block not found at head 2");
  const artifactStanding = await owner.call("vault.questions.create",
    { definition: judg02ArtifactDef(fixture.question.text, artifactRef, [blockHead2.id], v1.criteria) });
  const artifactStandingId = artifactStanding.definition.question.id;
  expect(artifactStandingId).not.toBe(fixture.answeredQuestion);
  expect(artifactStandingId).not.toBe(fixture.pairedQuestion);
  expect(artifactStanding.definition.adapter).toBe("artifact");
  expect(artifactStanding.definition.units).toEqual([]);
  const artifactRefreshV1 = await owner.call("vault.questions.refresh", { id: artifactStandingId });
  expect(artifactRefreshV1).toHaveLength(1);
  const askRowV1 = artifactRefreshV1[0]!;
  if (askRowV1.kind !== "artifact") throw new Error("Standing artifact refresh returned no artifact ask");
  expect(askRowV1.question_version).toBe(1);
  expect(askRowV1.artifact_version).toBe(2);
  expect(askRowV1.standing).toEqual({ state: "waiting" });
  if (!askRowV1.proposal_ref) throw new Error("Standing artifact v1 ask held no proposal");
  expect(typeof askRowV1.ask_id).toBe("string");
  const standingProposals = await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef });
  expect(standingProposals.map(row => row.proposal_ref)).toEqual([askRowV1.proposal_ref]);
  expect(standingProposals[0]!.base_version).toBe(2);
  expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(2);
  const keptV1 = await owner.call("vault.artifacts.keep", { artifact_ref: artifactRef, proposal_ref: askRowV1.proposal_ref });
  expect(keptV1.version.version).toBe(3);
  expect(keptV1.stranded).toBe(false);
  expect(keptV1.review?.paragraph_judgments).toHaveLength(1);
  const judgmentV1 = keptV1.review!.paragraph_judgments[0]!;
  expect(judgmentV1.block).toBe(blockHead2.id);
  expect(judgmentV1.decision.answer).toEqual({ kind: "noul", value: true });
  expect(judgmentV1.decision.probability).toBe(0.9);
  expect(judgmentV1.decision.receipt.question).toBe(artifactStandingId);
  expect(judgmentV1.decision.receipt.question_version).toBe(1);
  expect(judgmentV1.decision.receipt.principal).toBe(ownerRef);
  expect(judgmentV1.decision.receipt.providers).toEqual([judg02RulePin, judg02BigPin]);
  expect(judgmentV1.decision.receipt.paired ?? []).toEqual([]);
  expect(judgmentV1.author).toBe("fixture");
  expect(judgmentV1.labels).toEqual(judg02Labels);
  expect(judgmentV1.comment.split(": ")[1]).toBe("yes");
  const keptAnswersV1 = judg02AnswersList(await owner.call("vault.questions.answers", { id: artifactStandingId }));
  expect(keptAnswersV1).toHaveLength(1);
  if (keptAnswersV1[0]!.kind !== "artifact") throw new Error("Kept v1 ask did not read back");
  expect(keptAnswersV1[0].standing).toEqual({ state: "kept", version: 3 });
  const exportStandingV1 = (await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 3 }))?.content_base64;
  expect(typeof exportStandingV1).toBe("string");
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 2 }))?.content_base64).toBe(exportOneOff);
  await owner.call("vault.artifacts.body.import", { artifact_ref: artifactRef });
  const bodyReadHead3 = await owner.call("vault.artifacts.body.read", { artifact_ref: artifactRef });
  if (bodyReadHead3.format !== "docx") throw new Error("Parity live body is not docx at head 3");
  const blockHead3 = bodyReadHead3.body.blocks.find(row => row.text === paragraphText);
  if (!blockHead3) throw new Error("Parity paragraph block not found at head 3");
  await owner.call("vault.questions.edit", { id: artifactStandingId, expected_version: 1,
    definition: judg02ArtifactDef(fixture.question.text, artifactRef, [blockHead3.id], v2.criteria) });
  const artReadV1 = await owner.call("vault.questions.read", { id: artifactStandingId, version: 1 });
  expect(artReadV1?.definition.criteria).toEqual(v1.criteria);
  expect(artReadV1?.definition.question.version).toBe(1);
  expect(artReadV1?.definition.artifacts?.[0]?.selection).toMatchObject({ kind: "paragraphs", blocks: [blockHead2.id] });
  const artReadHead = await owner.call("vault.questions.read", { id: artifactStandingId });
  expect(artReadHead?.definition.criteria).toEqual(v2.criteria);
  expect(artReadHead?.definition.question.version).toBe(2);
  const artifactRefreshV2 = await owner.call("vault.questions.refresh", { id: artifactStandingId });
  expect(artifactRefreshV2).toHaveLength(2);
  expect(artifactRefreshV2.filter(row => row.kind === "artifact" && row.question_version === 1)).toEqual(keptAnswersV1);
  const askRowV2 = artifactRefreshV2.find(row => row.kind === "artifact" && row.question_version === 2);
  if (!askRowV2 || askRowV2.kind !== "artifact") throw new Error("Standing artifact v2 ask missing");
  expect(askRowV2.artifact_version).toBe(3);
  expect(askRowV2.standing).toEqual({ state: "unanswered" });
  expect(askRowV2.proposal_ref ?? null).toBeNull();
  expect(typeof askRowV2.ask_id).toBe("string");
  expect(askRowV2.units).toHaveLength(1);
  const artifactV2Unit = askRowV2.units?.[0];
  if (!artifactV2Unit || artifactV2Unit.status !== "abstained") throw new Error("Artifact C2 did not retain its abstention receipt");
  expect(artifactV2Unit.decision?.answer).toEqual({ kind: "abstain" });
  expect(artifactV2Unit.decision?.receipt).toMatchObject({ question: artifactStandingId,
    question_version: 2, principal: ownerRef, providers: [judg02RulePin, judg02BigPin] });
  expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
  expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(3);
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 2 }))?.content_base64).toBe(exportOneOff);
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 3 }))?.content_base64).toBe(exportStandingV1);
  expect(providers.seenFixtureCalls).toHaveLength(4);
  const artDecision = judg02Decision(questionV1.id, 1, ownerRef, [fixture.validPair]);
  const artAdmitAsk: FacadeInput<"vault.artifacts.ask"> = { artifact_ref: artifactRef,
    run_ref: "judg02-admit-v1", question: questionV1,
    units: { kind: "paragraphs", blocks: [blockHead3.id], author: "fixture", labels: judg02Labels },
    unit_budget_ms: 2000, deadline_ms: 8000 };
  const artAdmitted = await owner.call("vault.artifacts.admit", { ask: artAdmitAsk, decisions: [artDecision] });
  if (!artAdmitted.proposed) throw new Error("Artifact admission held no proposal");
  expect(artAdmitted.abstained).toEqual([]);
  expect(artAdmitted.refused).toEqual([]);
  expect(artAdmitted.proposed.base_version).toBe(3);
  expect((await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).map(row => row.proposal_ref))
    .toEqual([artAdmitted.proposed.proposal_ref]);
  expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(3);
  const keptAdmit = await owner.call("vault.artifacts.keep",
    { artifact_ref: artifactRef, proposal_ref: artAdmitted.proposed.proposal_ref });
  expect(keptAdmit.version.version).toBe(4);
  expect(keptAdmit.review?.paragraph_judgments).toHaveLength(1);
  expect(keptAdmit.review!.paragraph_judgments[0]!.decision.receipt.paired).toEqual([fixture.validPair]);
  expect(keptAdmit.review!.paragraph_judgments[0]!.decision.receipt.providers).toEqual([judg02Pin]);
  expect(keptAdmit.review!.paragraph_judgments[0]!.decision.answer).toEqual({ kind: "noul", value: true });
  expect(keptAdmit.review!.paragraph_judgments[0]!.decision.receipt.question).toBe(questionV1.id);
  const exportAdmit = (await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 4 }))?.content_base64;
  await owner.call("vault.artifacts.body.import", { artifact_ref: artifactRef });
  const bodyReadHead4 = await owner.call("vault.artifacts.body.read", { artifact_ref: artifactRef });
  if (bodyReadHead4.format !== "docx") throw new Error("Parity live body is not docx at head 4");
  const blockHead4 = bodyReadHead4.body.blocks.find(row => row.text === paragraphText);
  if (!blockHead4) throw new Error("Parity paragraph block not found at head 4");
  const beforeArtInvalid = providers.seenFixtureCalls.length;
  const artInvalidRuns = ["judg02-admit-dup", "judg02-admit-wrong", "judg02-admit-self", "judg02-admit-zero", "judg02-admit-range"];
  for (let index = 0; index < invalidPairs.length; index++) {
    const vector = invalidPairs[index]!;
    await judg02Error(() => owner.call("vault.artifacts.admit", { ask: { ...artAdmitAsk, run_ref: artInvalidRuns[index]!,
        units: { kind: "paragraphs", blocks: [blockHead4.id], author: "fixture", labels: judg02Labels } },
      decisions: [{ ...artDecision, receipt: { ...artDecision.receipt, paired: vector.paired } }] }), 400, "BAD_REQUEST");
    expect(providers.seenFixtureCalls).toHaveLength(beforeArtInvalid);
    expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
    expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(4);
  }
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 4 }))?.content_base64).toBe(exportAdmit);
  const claimsBeforeFailures = await judg02ClaimIds(owner, noteRef);
  const refreshedGraphV2 = await owner.call("vault.questions.refresh", { id: standingId });
  expect(refreshedGraphV2).toHaveLength(1);
  const graphV2 = refreshedGraphV2[0];
  if (!graphV2 || graphV2.kind !== "graph") throw new Error("Standing graph C2 result is missing");
  expect(graphV2.decision.answer).toEqual({ kind: "abstain" });
  expect(graphV2.decision.probability ?? null).toBeNull();
  expect(graphV2.decision.receipt).toMatchObject({ question: standingId, question_version: 2,
    principal: ownerRef, providers: [judg02RulePin, judg02BigPin] });
  const graphVersions = judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }));
  expect(graphVersions).toHaveLength(2);
  expect(graphVersions.find(row => row.kind === "graph" && row.decision.receipt.question_version === 1))
    .toEqual({ ...admittedV1, kind: "graph" });
  expect(graphVersions.find(row => row.kind === "graph" && row.decision.receipt.question_version === 2))
    .toEqual(graphV2);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual([...claimsBeforeFailures, graphV2.claim].sort());
  const claimsBeforeProviderFailures = await judg02ClaimIds(owner, noteRef);
  const garbageAsk: FacadeInput<"vault.artifacts.ask"> = { ...artAdmitAsk, run_ref: "judg02-garbage",
    units: { kind: "paragraphs", blocks: [blockHead4.id], author: "fixture", labels: judg02Labels } };
  const garbage = judg02NarrowAsk(await owner.call("vault.artifacts.ask", garbageAsk));
  expect(garbage.proposed).toBeNull();
  expect(garbage.refused).toEqual([]);
  expect(garbage.abstained).toHaveLength(1);
  expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
  expect((await owner.call("vault.artifacts.view", { artifact_ref: artifactRef }))?.head).toBe(4);
  const failed = await owner.call("vault.graph.ask", { question: questionV1, units: [noteRef],
    ceiling: "big", unit_deadline_ms: 2000 });
  if (failed.state !== "failed") throw new Error("Refused provider did not fail the graph ask");
  expect(failed.failed_unit).toBe(noteRef);
  expect(failed.code).toBe("BAD_REQUEST");
  expect(failed.message).toContain("big rung");
  expect(failed.answers).toEqual([]);
  expect(failed.abstained).toEqual([]);
  expect(failed.declined).toEqual([]);
  expect((await owner.call("vault.get", { entity_ref: noteRef })).value).toEqual(noteBaseline);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual(claimsBeforeProviderFailures);
  expect(providers.seenFixtureCalls).toHaveLength(7);
  expect(await peerAgent.client.call("vault.receipts.get", { receipt_ref: refusalRefs[0]! })).toBeNull();
  expect(await peerAgent.client.call("vault.receipts.get", { receipt_ref: "call:notahexreceiptref00000000000000" })).toBeNull();
  expect(await owner.call("vault.receipts.get", { receipt_ref: "call:00000000000000000000000000000000" })).toBeNull();
  const savedStandingV1 = await owner.call("vault.questions.read", { id: standingId, version: 1 });
  const savedStandingHead = await owner.call("vault.questions.read", { id: standingId });
  const savedStandingAnswers = judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }));
  const savedArtV1 = await owner.call("vault.questions.read", { id: artifactStandingId, version: 1 });
  const savedArtHead = await owner.call("vault.questions.read", { id: artifactStandingId });
  const savedArtAnswers = judg02AnswersList(await owner.call("vault.questions.answers", { id: artifactStandingId }));
  const savedView = await owner.call("vault.artifacts.view", { artifact_ref: artifactRef });
  const savedClaims = await judg02ClaimIds(owner, noteRef);
  await engine.restart();
  expect(await owner.call("vault.questions.read", { id: standingId, version: 1 })).toEqual(savedStandingV1);
  expect(await owner.call("vault.questions.read", { id: standingId })).toEqual(savedStandingHead);
  expect(judg02AnswersList(await owner.call("vault.questions.answers", { id: standingId }))).toEqual(savedStandingAnswers);
  expect(await owner.call("vault.questions.read", { id: artifactStandingId, version: 1 })).toEqual(savedArtV1);
  expect(await owner.call("vault.questions.read", { id: artifactStandingId })).toEqual(savedArtHead);
  expect(judg02AnswersList(await owner.call("vault.questions.answers", { id: artifactStandingId }))).toEqual(savedArtAnswers);
  expect(await owner.call("vault.artifacts.view", { artifact_ref: artifactRef })).toEqual(savedView);
  expect(await owner.call("vault.artifacts.proposals", { artifact_ref: artifactRef })).toEqual([]);
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 2 }))?.content_base64).toBe(exportOneOff);
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 3 }))?.content_base64).toBe(exportStandingV1);
  expect((await owner.call("vault.artifacts.export", { artifact_ref: artifactRef, version: 4 }))?.content_base64).toBe(exportAdmit);
  expect((await owner.call("vault.get", { entity_ref: noteRef })).value).toEqual(noteBaseline);
  expect(await judg02ClaimIds(owner, noteRef)).toEqual(savedClaims);
  for (const receiptRef of refusalRefs)
    expect((await owner.call("vault.receipts.get", { receipt_ref: receiptRef }))?.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
  expect(providers.seenFixtureCalls).toHaveLength(7);
  const calls = providers.seenFixtureCalls;
  expect(calls.map(call => call.fixtureId)).toEqual(["judg02-graph-v1", "judg02-artifact-v1",
    "judg02-standing-artifact-v1", "judg02-standing-artifact-v2", "judg02-graph-v2-abstain",
    "judg02-artifact-garbage", "judg02-graph-auth-fail"]);
  for (const call of calls) {
    expect(call).toMatchObject({ method: "POST", path: "/v1/chat/completions", origin: "parity", role: "checker" });
    const sent = call.body as { model?: unknown; stream?: unknown; messages?: { role?: unknown; content?: unknown }[] };
    expect(sent.model).toBe(judg02WireModel);
    expect(sent.stream).toBe(false);
    expect(sent.messages?.[0]?.role).toBe("system");
    expect(JSON.stringify(sent.messages?.[0])).toContain(judg02Wording);
    expect(sent.messages?.[1]?.role).toBe("user");
  }
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
  } finally {
    try { await engine.close(); } finally { await providers.close(); }
  }
});

interface judg03StandingFixture {
  scenario: string;
  unit: { alias: string; text: string };
  question: { text: string; contract: { kind: string } };
  definition: {
    adapter: string;
    activation: string;
    refresh: { on_arrival: boolean; every_seconds: number };
    learning: boolean;
    audience: string;
    dial: { first: string; ceiling: string; band: { low: number; high: number } };
  };
  binding: {
    source: { kind: string; predicate: string };
    horizon: number;
    mapping: Record<string, boolean>;
    noise_weight: number;
  };
  prediction: { answer: { kind: string; value: boolean }; probability: number };
  outcome: { value: string; withinHorizon: boolean; source: string; repeat: string };
  expected: {
    standingRecords: number;
    outcomeLabelsAfterArrival: number;
    outcomeLabelsAfterReplay: number;
    mappedLabel: boolean;
    noiseWeight: number;
    linkFields: string[];
    afterPause: string;
  };
}
// The System One wire model: the seat's `<model>-<version>`, named by both sides.
const judg03S1_MODEL = "fixture-standing-e2e-v1";
const judg03PACK = "e2e.judgments";
const judg03PREDICATE = "e2e.judgments.fulfillment";
function judg03PackMd(): string {
  return [
    "---",
    `name: ${judg03PACK}`,
    "description: Independently authored standing question fixture",
    "version: 1",
    "kind: capability",
    `predicates: ["${judg03PREDICATE}"]`,
    "---",
    "",
  ].join("\n");
}
// Chosen public input ids, not purported existing engine handles.
function judg03EntityId(label: string): string {
  return createHash("sha256").update(`judgments-03:${label}`).digest("hex").slice(0, 32);
}
// BLAKE3 over the MessagePack of the outcome value, as the projector hashes it.
function judg03FulfilledHash(): number[] {
  const word = new TextEncoder().encode("fulfilled");
  const packed = new Uint8Array(1 + word.length);
  packed[0] = 0xa9; // MessagePack fixstr of length 9.
  packed.set(word, 1);
  return Array.from(blake3(packed));
}
function judg03GraphAnswers(
  reply: FacadeResult<"vault.questions.answers"> | FacadeResult<"vault.questions.refresh">,
): Extract<QuestionAnswer, { kind: "graph" }>[] {
  const list = Array.isArray(reply) ? reply : reply.answers;
  return list.filter((row): row is Extract<QuestionAnswer, { kind: "graph" }> => row.kind === "graph");
}
async function judg03HttpRefusal<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, verb: V, input: FacadeInput<V>,
  status: number, code: string,
) {
  let failure: unknown;
  try { await client.call(verb, input); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`Expected public refusal for ${verb}`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  const receiptRef = failure.error?.receiptRef;
  expect(receiptRef).toEqual(expect.stringMatching(/^call:[a-f0-9]{32}$/));
  if (typeof receiptRef !== "string") throw new Error(`Missing refusal receipt for ${verb}`);
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  // The owner reads every receipt back; a caller without Read scope could not read its own.
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `judg03 refusal receipt ${verb}` });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport: "http_facade",
    verb: `v1/core/facade/${verb}`, outcome: { refused: { code } } });
  return { failure, receipt };
}

/* JUDGMENTS-03 — Standing question and outcome binding should work.
 * Fixture: judgments-standing (standing.json). OF-516/506.
 *
 * Proves the full manual journey, on one engine, without waiting for any
 * timer: install the fixture predicate through the public pack contract;
 * create ONE standing graph definition and read back its horizon, mapping
 * and noise weight; answer it once via manual refresh on the bound System
 * One first rung; write the later fulfilled fact through its ordinary gate
 * and project it; assert exactly one label links that answer to that fact
 * with the mapped true value, 0.75 weight and exact hash/time; replay the
 * same fact identity and keep exactly one label; pause and observe no
 * further provider work on manual refresh while the definition, answer and
 * label stay readable; survive a restart with the same public state. Scope
 * refusals and foreign-principal absence carry receipted refusals; every
 * write is read back second-door.
 *
 * Setup the promise needs: the fixture predicate alias is remapped to the
 * author-scoped e2e.judgments.fulfillment the pack contract requires; a
 * separately granted agent asks so the owner can settle its proposals; the
 * outcome fact reuses the answer's own public timestamp, inside its horizon.
 * The first rung is a real bound seat, never an absence another rung skips.
 * Not proved (not promised here): a due daily tick (every_seconds is read
 * back, never awaited), a provider-failure refresh, and post-revoke
 * question visibility (history reads stay before the revoke; the revoke
 * itself is proved through the registry at the end).
 */
suite.test(test, "JUDGMENTS-03", "Standing question answers on refresh, binds its later outcome to one label, replays the same fact without a second label, and keeps its history readable but silent across pause and restart", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<judg03StandingFixture>("judgments-standing");
  expect(fixture.scenario).toBe("JUDGMENTS-03");
  // The pack contract needs an author-scoped predicate; remap the alias, never send it literally.
  expect(fixture.binding.source).toEqual({ kind: "claim", predicate: "fixture.fulfillment" });
  const predicate = fixture.binding.source.predicate.replace(/^fixture\./, `${judg03PACK}.`);
  expect(predicate).toBe(judg03PREDICATE);
  expect(fixture.definition.adapter).toBe("graph");
  expect(fixture.definition.activation).toBe("standing");
  expect(fixture.definition.learning).toBe(true);
  expect(fixture.definition.audience).toBe("asker");
  expect(fixture.definition.dial.first).toBe("system_one");
  expect(fixture.definition.dial.ceiling).toBe("big");
  expect(fixture.question.contract).toEqual({ kind: "noul" });
  expect(fixture.prediction.answer).toEqual({ kind: "noul", value: true });
  expect(fixture.outcome.source).toBe("user_stated");
  const providers = await ScriptedProviders.start({ id: "JUDGMENTS-03",
    steps: [{
      id: "judg03-refresh",
      origin: "standing",
      role: "system_one",
      purpose: "judg03 standing refresh",
      request: { method: "POST", path: "/v1/systemone", model: judg03S1_MODEL,
        fields: { questions: { decision: { type: "noul" } } } },
      response: { kind: "json", body: { model: judg03S1_MODEL,
        answers: { decision: { type: "noul", noul: fixture.prediction.probability } },
        usage: { input_tokens: 20, output_tokens: 4 } } },
    }],
  });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "JUDGMENTS-03", profile, serverConfig: `
[models.decisions.system_one]
endpoint = "${providers.urls.standing}/v1/systemone"
key_env = "TZ"
model = "fixture-standing"
version = "e2e-v1"
remote_opt_in = true
[models.dreamer]
enabled = false
` });
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const baseScope = await ownerBaseClaimScope(owner, ownerRef);
    const installed = await owner.call("vault.packs.put", { files: [{ path: "PACK.md", text: judg03PackMd() }] });
    expect(installed.outcome).toBe("installed");
    expect(installed.receipt?.pack_name).toBe(judg03PACK);
    expect(installed.receipt?.status).toBe("active");
    expect(installed.receipt?.predicates).toContain(judg03PREDICATE);
    const packBack = await owner.call("vault.packs.get", { name: judg03PACK });
    expect(packBack?.pack_name).toBe(judg03PACK);
    expect(packBack?.status).toBe("active");
    expect(packBack?.predicates).toContain(judg03PREDICATE);
    const note = await owner.call("vault.notes.create", { kind: "research", markdown: fixture.unit.text });
    const unitId = note.id_hex;
    expect(unitId).toMatch(/^[a-f0-9]{32}$/);
    expect((await owner.call("vault.get", { entity_ref: unitId })).value?.id_hex).toBe(unitId);
    const askerRef = judg03EntityId("asker");
    await owner.call("vault.agents.create", { agent_def_ref: askerRef, definition: {
      agent_id: "judg03-asker", display_name: "Standing question asker",
      desc: "Asks the standing question so the owner can settle its proposals", version: "1" } });
    expect((await owner.call("vault.get", { entity_ref: askerRef })).value?.kind).toBe("AGENT_DEF");
    const asker = await engine.pairActor({ principalRef: askerRef, actorClass: "agent" });
    expect(await asker.client.call("self.actor", {})).toMatchObject({ actor_ref: askerRef, actor_class: "agent" });
    const grant = await owner.call("vault.agents.grants.mint", {
      agent: askerRef,
      authority_scope: {
        worlds: { kind: "some", values: [baseScope.world_id] },
        facets: { kind: "some", values: [baseScope.scope_facet_id] },
        audience: { kind: "some", values: [baseScope.scope_project_id] },
        bands: { kind: "all" },
        verbs: { kind: "some", values: ["read", "write"] },
        sensitivity: { kind: "all" },
      },
    });
    expect(grant.grant.confers).toBe(true);
    expect(grant.grant.agent).toBe(askerRef);
    expect(grant.grant.grant_ref).toMatch(/^[a-f0-9]{32}$/);
    const registryLive = await owner.call("vault.consent.registry", { limit: 50, include_revoked: false });
    const liveRow = registryLive.rows.find(row => row.grant_ref === grant.grant.grant_ref);
    expect(liveRow?.status).toBe("active");
    expect(liveRow?.class).toBe("agent_grant");
    expect(liveRow?.agent_grant?.agent).toBe(askerRef);
    expect(liveRow?.agent_grant?.delegated_by).toBe(ownerRef);
    expect(liveRow?.agent_grant?.confers).toBe(true);
    expect(liveRow?.revoke_action).toEqual({ command: "vault.agents.grants.revoke",
      grant_ref: grant.grant.grant_ref });
    expect(liveRow?.scope?.verbs).toEqual({ kind: "some", values: ["read", "write"] });
    const foreignRef = judg03EntityId("foreigner");
    await owner.call("vault.agents.create", { agent_def_ref: foreignRef, definition: {
      agent_id: "judg03-foreigner", display_name: "Standing question foreigner",
      desc: "Inert principal for foreign-question absence", version: "1" } });
    expect((await owner.call("vault.get", { entity_ref: foreignRef })).value?.kind).toBe("AGENT_DEF");
    const foreigner = await engine.pairActor({ principalRef: foreignRef, actorClass: "agent" });
    expect(await foreigner.client.call("self.actor", {}))
      .toMatchObject({ actor_ref: foreignRef, actor_class: "agent" });
    const readOnly = await engine.pairActor({ principalRef: askerRef, actorClass: "agent", scope: ["core:read"] });
    const writeOnly = await engine.pairActor({ principalRef: askerRef, actorClass: "agent", scope: ["core:write"] });
    // One standing definition; the dial sits inside the host's, the band equals its default.
    const definition = {
      question: { text: fixture.question.text, class: "judgment",
        contract: { kind: "noul" }, accept_type: false },
      adapter: "graph",
      units: [unitId],
      recipe: "fixture",
      profile: "fixture",
      dial: { first: "system_one", ceiling: "big", band: { ...fixture.definition.dial.band } },
      activation: "standing",
      refresh: { ...fixture.definition.refresh },
      delivery: "fixture",
      learning: fixture.definition.learning,
      binding: { source: { kind: "claim", predicate },
        horizon: fixture.binding.horizon, mapping: { ...fixture.binding.mapping },
        noise_weight: fixture.binding.noise_weight },
      audience: "asker",
      deadline_ms: 2000,
    } satisfies FacadeInput<"vault.questions.create">["definition"];
    const created = await asker.client.call("vault.questions.create", { definition });
    const questionId = created.definition.question.id;
    expect(questionId).toMatch(/^[a-f0-9]{32}$/);
    expect(created.definition.question.version).toBe(1);
    expect(created.principal).toBe(askerRef);
    const stored = await asker.client.call("vault.questions.read", { id: questionId });
    expect(stored?.principal).toBe(askerRef);
    expect(stored?.definition.binding).toEqual(definition.binding);
    expect(stored?.definition.dial).toEqual(definition.dial);
    expect(stored?.definition.units).toEqual([unitId]);
    expect(stored?.definition.refresh).toEqual(definition.refresh);
    expect(stored?.definition.learning).toBe(true);
    expect(stored?.definition.question).toMatchObject({ id: questionId, version: 1, text: fixture.question.text });
    expect(fixture.expected.standingRecords).toBe(1);
    const scheduleBefore = await asker.client.call("vault.questions.schedule", { id: questionId });
    expect(scheduleBefore).toMatchObject({ id: questionId, version: 1, paused: false });
    expect(scheduleBefore?.last_refresh ?? null).toBeNull();
    expect(scheduleBefore?.retry_at ?? null).toBeNull();
    const outcomesBefore = await asker.client.call("vault.questions.outcomes", { id: questionId });
    expect(outcomesBefore.labels).toEqual([]);
    expect(outcomesBefore.calibration).toEqual([]);
    // Manual refresh answers now on the bound System One first seat.
    const refreshed = await asker.client.call("vault.questions.refresh", { id: questionId });
    const fresh = judg03GraphAnswers(refreshed);
    expect(fresh).toHaveLength(1);
    const answer = fresh[0]!;
    expect(answer.unit).toBe(unitId);
    expect(answer.claim).toMatch(/^[a-f0-9]{32}$/);
    expect(answer.answered_at).toBeGreaterThan(0);
    expect(Array.isArray(answer.frontier)).toBe(true);
    expect(answer.decision.answer).toEqual({ kind: "noul", value: fixture.prediction.answer.value });
    expect(answer.decision.probability).toBe(fixture.prediction.probability);
    expect(answer.decision.in_band).toBe(false);
    expect(Array.isArray(answer.decision.evidence)).toBe(true);
    expect(answer.decision.receipt.question).toBe(questionId);
    expect(answer.decision.receipt.question_version).toBe(1);
    expect(answer.decision.receipt.principal).toBe(askerRef);
    expect(answer.decision.receipt.band).toEqual(fixture.definition.dial.band);
    expect(answer.decision.receipt.providers).toEqual([
      { rung: "system_one", model: "fixture-standing", version: "e2e-v1" },
    ]);
    expect(answer.decision.receipt.paired ?? []).toEqual([]);
    expect(answer.decision.receipt.person ?? []).toEqual([]);
    expect(providers.seenFixtureCalls).toHaveLength(1);
    expect(providers.seenFixtureCalls[0]).toMatchObject({ method: "POST", path: "/v1/systemone" });
    expect(providers.seenFixtureCalls[0]!.body).toMatchObject({ model: judg03S1_MODEL });
    // Second door for the refresh: the answers log. The schedule head stays
    // untouched: only a scheduled tick writes the refresh clock, never a manual call.
    expect(judg03GraphAnswers(await asker.client.call("vault.questions.answers", { id: questionId }))).toEqual([answer]);
    const scheduleAnswered = await asker.client.call("vault.questions.schedule", { id: questionId });
    expect(scheduleAnswered).toEqual(scheduleBefore);
    expect(scheduleAnswered?.last_refresh ?? null).toBeNull();
    expect(scheduleAnswered?.retry_at ?? null).toBeNull();
    // The prediction lands proposed; the owner settles it so it can bind.
    const review = await owner.call("vault.claims.review", { claim_ref: answer.claim });
    expect(review.claim.approval).toBe("proposed");
    expect(review.claim.predicate).toBe("judgment.answer");
    expect(review.claim.subject_ref).toBe(unitId);
    const settled = await owner.call("vault.claims.settle", {
      claim_ref: answer.claim, review_id: review.review_id, decision: "approve" });
    expect(settled.review_id).toBe(review.review_id);
    expect(settled.proposal_ref).toBe(review.proposal_ref);
    expect(settled.verdict).toBe("landed");
    expect(settled.changes).toEqual([{ claim_ref: answer.claim, verdict: "landed" }]);
    expect(settled.answered_by).toEqual({ kind: "word", person_ref: ownerRef });
    expect(settled.reason).toBe("gate.claim.settle.approved");
    const predictionHistory = (await owner.call("vault.claims.history", { claim_ref: answer.claim })).value;
    expect(predictionHistory).toHaveLength(1);
    expect(predictionHistory[0]).toMatchObject({ claim_ref: answer.claim, predicate: "judgment.answer",
      subject_ref: unitId, approval: "approved", lifecycle: "active" });
    // The later fact reuses the answer's own public timestamp: inside its horizon, no clock of ours.
    const factId = judg03EntityId("outcome-fact");
    const factInput = {
      id: factId,
      predicate,
      subject_ref: unitId,
      value: fixture.outcome.value,
      confidence: 1,
      source: fixture.outcome.source,
      scope: baseScope,
      occurred_at: answer.answered_at,
      learned_at: answer.answered_at,
    } satisfies FacadeInput<"vault.claims.upsert">;
    const landed = await owner.call("vault.claims.upsert", factInput);
    expect(landed.approval).toBe("auto");
    expect(landed.superseded_short_id ?? null).toBeNull();
    expect((await owner.call("vault.get", { entity_ref: landed.claim_short_id })).value?.id_hex).toBe(factId);
    // Arrival may already have bound it; the explicit projection is idempotent either way.
    const projected = await asker.client.call("vault.questions.outcomes.project", { id: questionId });
    expect(projected).toMatchObject({ id: questionId });
    expect([0, 1]).toContain(projected.projected);
    const outcomes = await asker.client.call("vault.questions.outcomes", { id: questionId });
    expect(outcomes.labels).toHaveLength(fixture.expected.outcomeLabelsAfterArrival);
    const label = outcomes.labels[0]!;
    expect(label).toEqual({ answer: answer.claim, fact: factId,
      fact_value_hash: judg03FulfilledHash(), label: fixture.expected.mappedLabel,
      noise_weight: fixture.expected.noiseWeight, occurred_at: answer.answered_at });
    for (const field of fixture.expected.linkFields) expect(label).toHaveProperty(field);
    expect(outcomes.calibration).toHaveLength(1);
    const pair = outcomes.calibration[0]!;
    expect(pair.prediction).toEqual({ kind: "noul", value: fixture.prediction.answer.value });
    expect(pair.probability).toBe(fixture.prediction.probability);
    expect(pair.outcome).toEqual(label);
    expect(pair.question_version).toBe(1);
    expect(pair.providers).toEqual(answer.decision.receipt.providers);
    expect(pair.route).toMatchObject({ kind: "direct", rung: "system_one" });
    // Replay the same accepted fact identity: still one label, never a second example.
    const replayed = await owner.call("vault.claims.upsert", factInput);
    expect(replayed.approval).toBe("auto");
    expect(replayed.claim_short_id).toBe(landed.claim_short_id);
    expect(replayed.superseded_short_id ?? null).toBeNull();
    const reprojected = await asker.client.call("vault.questions.outcomes.project", { id: questionId });
    expect(reprojected).toEqual({ id: questionId, projected: 0 });
    const outcomesReplayed = await asker.client.call("vault.questions.outcomes", { id: questionId });
    expect(outcomesReplayed.labels).toHaveLength(fixture.expected.outcomeLabelsAfterReplay);
    expect(outcomesReplayed.labels).toEqual([label]);
    expect(outcomesReplayed.calibration).toEqual([pair]);
    // Pause: no scheduled or manual provider work, history still readable.
    expect(await asker.client.call("vault.questions.pause", { id: questionId, paused: true }))
      .toEqual({ id: questionId, paused: true });
    const schedulePaused = await asker.client.call("vault.questions.schedule", { id: questionId });
    expect(schedulePaused).toMatchObject({ id: questionId, version: 1, paused: true });
    expect(schedulePaused?.last_refresh ?? null).toBeNull();
    expect(schedulePaused?.retry_at ?? null).toBeNull();
    expect(await asker.client.call("vault.questions.refresh", { id: questionId })).toEqual([]);
    expect(providers.seenFixtureCalls).toHaveLength(1);
    expect(await asker.client.call("vault.questions.read", { id: questionId })).toEqual(stored);
    expect(judg03GraphAnswers(await asker.client.call("vault.questions.answers", { id: questionId }))).toEqual([answer]);
    expect(await asker.client.call("vault.questions.outcomes", { id: questionId })).toEqual(outcomesReplayed);
    expect(fixture.expected.afterPause).toContain("no scheduled or manual provider work");
    // Wrong scope: every write door refuses a read-only caller, every read door a write-only one.
    const refusedCreate = await judg03HttpRefusal(engine, readOnly.client,
      "vault.questions.create", { definition }, 403, "FORBIDDEN");
    expect(refusedCreate.receipt).toMatchObject({ actor_ref: askerRef, actor_class: "agent" });
    await judg03HttpRefusal(engine, readOnly.client, "vault.questions.refresh", { id: questionId }, 403, "FORBIDDEN");
    await judg03HttpRefusal(engine, readOnly.client, "vault.questions.outcomes.project", { id: questionId }, 403, "FORBIDDEN");
    await judg03HttpRefusal(engine, readOnly.client, "vault.questions.pause", { id: questionId, paused: true }, 403, "FORBIDDEN");
    const refusedRead = await judg03HttpRefusal(engine, writeOnly.client,
      "vault.questions.read", { id: questionId }, 403, "FORBIDDEN");
    expect(refusedRead.receipt).toMatchObject({ actor_ref: askerRef, actor_class: "agent" });
    await judg03HttpRefusal(engine, writeOnly.client, "vault.questions.schedule", { id: questionId }, 403, "FORBIDDEN");
    await judg03HttpRefusal(engine, writeOnly.client, "vault.questions.answers", { id: questionId }, 403, "FORBIDDEN");
    await judg03HttpRefusal(engine, writeOnly.client, "vault.questions.outcomes", { id: questionId }, 403, "FORBIDDEN");
    // Wrong principal: absence or not-found, never another caller's rows; projection binds none.
    expect(await foreigner.client.call("vault.questions.read", { id: questionId })).toBeNull();
    expect(await foreigner.client.call("vault.questions.schedule", { id: questionId })).toBeNull();
    await judg03HttpRefusal(engine, foreigner.client, "vault.questions.answers", { id: questionId }, 404, "NOT_FOUND");
    await judg03HttpRefusal(engine, foreigner.client, "vault.questions.outcomes", { id: questionId }, 404, "NOT_FOUND");
    await judg03HttpRefusal(engine, foreigner.client, "vault.questions.pause", { id: questionId, paused: false }, 404, "NOT_FOUND");
    await judg03HttpRefusal(engine, foreigner.client, "vault.questions.refresh", { id: questionId }, 404, "NOT_FOUND");
    expect(await foreigner.client.call("vault.questions.outcomes.project", { id: questionId }))
      .toEqual({ id: questionId, projected: 0 });
    expect(await asker.client.call("vault.questions.schedule", { id: questionId })).toEqual(schedulePaused);
    expect(await asker.client.call("vault.questions.outcomes", { id: questionId })).toEqual(outcomesReplayed);
    expect(providers.seenFixtureCalls).toHaveLength(1);
    // Restart: the paused head, definition, answer and label come back; nothing re-asks.
    await engine.restart();
    expect(await asker.client.call("vault.questions.schedule", { id: questionId })).toEqual(schedulePaused);
    expect(await asker.client.call("vault.questions.read", { id: questionId })).toEqual(stored);
    expect(judg03GraphAnswers(await asker.client.call("vault.questions.answers", { id: questionId }))).toEqual([answer]);
    const outcomesRestarted = await asker.client.call("vault.questions.outcomes", { id: questionId });
    expect(outcomesRestarted.labels).toEqual([label]);
    expect(outcomesRestarted.calibration).toEqual([pair]);
    expect(providers.seenFixtureCalls).toHaveLength(1);
    // The revoke lands and the registry proves it both ways; the case claims
    // nothing about question visibility after actual grant loss.
    const revoked = await owner.call("vault.agents.grants.revoke", { grant_ref: grant.grant.grant_ref });
    expect(revoked).toMatchObject({ grant_ref: grant.grant.grant_ref, changed: true, agent: askerRef });
    expect(revoked.act_ref).toEqual(expect.stringMatching(/^[a-f0-9]{64}$/));
    const registryAfter = await owner.call("vault.consent.registry", { limit: 50, include_revoked: false });
    expect(registryAfter.rows.find(row => row.grant_ref === grant.grant.grant_ref)).toBeUndefined();
    const registryAudit = await owner.call("vault.consent.registry", { limit: 50, include_revoked: true });
    const deadRow = registryAudit.rows.find(row => row.grant_ref === grant.grant.grant_ref);
    expect(deadRow?.status).toBe("revoked");
    expect(deadRow?.agent_grant?.confers).toBe(false);
    const revokedAgain = await owner.call("vault.agents.grants.revoke", { grant_ref: grant.grant.grant_ref });
    expect(revokedAgain.changed).toBe(false);
    expect(revokedAgain.agent ?? null).toBeNull();
    expect(providers.seenFixtureCalls).toHaveLength(1);
  } finally {
    try { await engine?.close(); } finally { await providers.close(); }
  }
});

// No helpers: this case has no public setup path on a fresh served vault.

/* JUDGMENTS-04 — Saved query cache and live membership should work.
 * Fixture: judgments-saved-query (saved-query.json). OF-403.
 * self.saved_query.{create,read,update,archive,members,evaluate} are typed.
 * The missing door is owner/grant-checked SAVED_QUERY structural registration
 * for self.saved_query.create on a fresh served vault, not CRUD or memo reads.
 * Generic vault.packs.install cannot install the compiled CRM registration.
 * Once that public setup exists: create scoped leads and a manual hard+judge
 * query; read membership through members; refuse another actor with its
 * receiptRef; restart and read the query, verdict memos and membership again.
 * Preserve the fixture's two/zero/one judgments, source-revision invalidation,
 * narrowed-owner reach and entered/exited causes. Manual evaluate currently
 * records verdicts without updating membership; do not make empty members a
 * passing cache-only replacement. No private registrar or vault seed is used.
 */
suite.todo(test, "JUDGMENTS-04", "waits on owner/grant-checked public SAVED_QUERY structural registration for self.saved_query.create on a fresh served vault (Saved query cache and live membership should work)");

/* JUDGMENTS-05 — Local retrieval telemetry and replay should work.
 * Fixture: judgments-telemetry (telemetry.json). OF-106/259/260/265.
 *
 * Current recall is {query,effort,scope?,limit?,as_of?,deadline_ms?,...} ->
 * MemoryPack {items,scope_honesty,retrieval_meta,pack_version,narrowing,...}.
 * Canon's instrumented run is RetrievalState/action plus run identity and a
 * separately linked outcome (run_id); trace is opt-in per-stage candidates.
 * A turn outcome names exact retrievalRunIds[], never guessed overlap.
 *
 * Activate: use two fresh independent vaults serially inside this one-slot
 * file (not EngineFixture.peers, which needs two slots). Exercise capture
 * off, capture on without trace, and explicitly enabled trace. Recall the
 * fixed corpus/query, attach an owned outcome to the public serving run,
 * export through supported local diagnostic CLI/HTTP, then repeat the same
 * pinned replay on the SAME vault. Compare ordered source IDs/stage values
 * and fork identity; ignore run occurrence IDs and wall-clock metadata.
 * Change policy, model revision and source frontier ONE AT A TIME; each
 * material change must change that vault's replay identity. Deny cross-vault
 * run reads and outcome attachment with no foreign mutation. The per-vault
 * keyed hashes are not a cross-tenant equality oracle. Exports must contain
 * no raw query, pack text, raw frontier samples or trace key.
 *
 * Blocker: recall exposes neither the telemetry run handle/trace nor typed
 * run/outcome/export/replay operations. The shipped CLI catalog has no such
 * diagnostic commands; oneiron-bench's internal-vault tooling is outside
 * the allowed public server/CLI surface. Generic oneiron api and full-vault
 * export do not supply the missing typed diagnostic contract. Do not persist
 * the query in a fabricated run row or compare hashes across vaults.
 */
suite.todo(test, "JUDGMENTS-05", "waits on typed retrieval run/outcome, trace and diagnostic replay/export doors (Local retrieval telemetry and replay should work)");

/* JUDGMENTS-06 — Learned retrieval policy retains owner pins should work.
 * Fixture: judgments-policy (policy.json). OF-092/093.
 *
 * Canon: RetrievalState/action + gated owned outcomes train the retrieval
 * skill's parameters at sleep. Immutable held-out queries/labels score a
 * candidate; declared owner pin/manifest weight stays authoritative.
 * learning.* is recorded/projector-only, not an ordinary claim write.
 * Existing vault.settings.learning{,.put,.clear} manages catalogued owner
 * seeds/pins; it is NOT a retrieval training or weight-table update call.
 *
 * Activate: publicly populate the fixed corpus, pin the selected weight to
 * 0.7, and snapshot that row and authoritative source claims. Attach the
 * training outcomes to their contributing runs, retain held-out labels only
 * for evaluation, and request the declared policy update. Read its candidate,
 * acceptance result, routing/model pins, weight origins, corpus digest and
 * accuracy/cost tradeoff. Submit a regression, an attempted pin overwrite,
 * foreign/ungated outcomes and an attempt to turn derived reward into fact.
 * Each must preserve the owner pin and original facts. An accepted update
 * may change only unpinned policy parameters inside its authority. This tiny
 * set cannot establish not-worse sufficiency: unknown stays an offer, never
 * an auto-approved switch or invented universal quality threshold.
 *
 * Blocker: no typed retrieval-outcome training/update, held-out policy
 * evaluation/admission or retrieval weight/routing receipt call exists in
 * the public HTTP/SDK catalog. The private blend tuner and generic learned
 * settings calls cannot stand in for OF-092's retrieval-policy loop. No
 * direct learning.* claims, private tuner calls or new production knobs.
 */
suite.todo(test, "JUDGMENTS-06", "waits on typed retrieval-policy training/evaluation/update and weight receipts (Learned retrieval policy retains owner pins should work)");

/* JUDGMENTS-07 — Prospective hints remain derived should work.
 * Fixture: judgments-hints (hints.json). OF-105.
 * Canon also: write-path #prospective-query, ARCH-0038 derived invalidation.
 *
 * Current WitnessTurn {conversation_ref,messages,occurred_at,...} and
 * vault.search.bm25({query,limit}) give the ingest/read ends. ClaimInput has
 * {predicate,subject_ref,value,confidence,source,...}, no prospective hints.
 * ConsolidationEnqueueRequest is {scope,input:unknown,run_id?,dedupe_key?,
 * now?}; status returns DreamerAttemptView, not a typed extraction result.
 *
 * Activate: witness the source and distractor through the public door.
 * Before extraction the fixture's query words have no literal lexical hit.
 * Run the scripted extractor to emit the fixed claim plus prospective query,
 * await its public completion, then search for the hint wording. Assert the
 * hit resolves to the source claim, carries the original turn/revision and
 * generated hint provenance, and is not an independent identity/evidence
 * claim. Erase the source through the owner-confirmed public deletion flow,
 * await its receipt and requery: no source or orphan hint survives, while
 * the independent distractor remains readable. A hint must never authorize
 * a write or be counted as another corroborating source.
 *
 * Blocker: no typed HTTP/SDK extraction producer/result carries prospective
 * queries or their source links. The consolidation input's unknown payload
 * is not a typed extraction call. No generic vault.batch/claim-value seed,
 * manually written lexical_query_hint, private batch builder or raw index
 * manipulation may fabricate a successful extractor for this scenario.
 */
suite.todo(test, "JUDGMENTS-07", "waits on typed extraction prospective-query output and completion/source receipts (Prospective hints remain derived should work)");
