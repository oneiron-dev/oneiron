import { afterAll, expect, test } from "bun:test";
import { verify } from "node:crypto";
import { EngineFixture } from "./support/engine.ts";
import { loadFixtures } from "./support/fixtures.ts";
import type { Profile } from "./support/fixtures.ts";
import type { PublicHttpClient, WireReply } from "./support/clients.ts";
import { defineFile } from "./support/run.ts";

const profile: Profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

// Non-facade DTOs from the existing OpenAPI UsageEvent/UsageRecordResult/
// UsageRollup schemas (consumer_usage.rs and usage/model.rs). These wire fields
// are camelCase, unlike generated facade DTOs. No model or vault internals run.
type UsageSource = "local" | "byo" | "oneiron_cloud";
interface TokenCounts {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}
interface CostRates {
  currency: string;
  priceTableSnapshot: string;
  inputPerMillion: number;
  outputPerMillion: number;
  cacheReadPerMillion: number;
  cacheWritePerMillion: number;
}
interface Money {
  amount: number;
  currency: string;
  priceTableSnapshot: string;
}
interface UsageEvent {
  owner: string;
  vaultId: string;
  idempotencyKey: string;
  source?: UsageSource;
  eventType: "inference" | "cache" | "service";
  role: string;
  occurredAt: number;
  agentId: string;
  model: string;
  service: string;
  tokenCounts: TokenCounts;
  costRates: CostRates;
  serviceAmount: number;
}
interface UsageCounter extends TokenCounts {
  eventCount: number;
  amountsByCurrency: Record<string, number>;
}
interface UsageRollup {
  owner: string;
  vaultId: string;
  counters: UsageCounter;
  agents: Record<string, UsageCounter>;
  models: Record<string, UsageCounter>;
  services: Record<string, UsageCounter>;
}
interface UsageRecordResult {
  recorded: boolean;
  replayed: boolean;
  source: UsageSource;
  cost: Money | null;
  vaultRollup: UsageRollup | null;
}
interface UsageApiError {
  code: string;
  message: string;
  details: { code: string; idempotencyKey?: string | null };
  suggestions: string[];
}
interface UsageModeFixture {
  configMode: "local_free" | "byo_cloud_key" | "oneiron_cloud";
  source: UsageSource;
  recordsBillingFacts: boolean;
}
interface EventFixture extends Omit<UsageEvent, "owner" | "vaultId" | "costRates"> {
  currency: string;
}
interface UsageFacts {
  owner: string;
  vaultId: string;
  otherVaultId: string;
  modes: UsageModeFixture[];
  events: [EventFixture, EventFixture];
  expected: {
    costs: [Money, Money];
    counters: UsageCounter;
    usdCounter: UsageCounter;
    eurCounter: UsageCounter;
    conflictCode: string;
    unmeteredRollupStatus: number;
  };
}
interface PriceTable { revision: string; rates: Record<string, CostRates> }

// Missing from the shared typed client: the existing non-facade usage doors.
// Keep these small wire helpers here; the prerequisite is on the fix list.
function submitUsage(client: PublicHttpClient, event: UsageEvent) {
  return client.raw<UsageRecordResult | UsageApiError>("POST", "/v1/usage/events", event);
}
function readUsage(client: PublicHttpClient, owner: string, vaultId: string) {
  return client.raw<UsageRollup | UsageApiError>("GET",
    `/v1/usage/owners/${encodeURIComponent(owner)}/vaults/${encodeURIComponent(vaultId)}/rollup`);
}
function usageEvent(facts: UsageFacts, event: EventFixture, table: PriceTable): UsageEvent {
  const { currency, ...fields } = event;
  const costRates = table.rates[currency];
  if (!costRates) throw new Error(`Unpriced fixture currency: ${currency}`);
  return { ...fields, owner: facts.owner, vaultId: facts.vaultId, costRates };
}
function expectedRollup(facts: UsageFacts, otherVault = false): UsageRollup {
  const [usd, eur] = facts.events;
  const expected = facts.expected;
  return {
    owner: facts.owner,
    vaultId: otherVault ? facts.otherVaultId : facts.vaultId,
    counters: otherVault ? expected.usdCounter : expected.counters,
    agents: { [usd.agentId]: otherVault ? expected.usdCounter : expected.counters },
    models: otherVault ? { [usd.model]: expected.usdCounter }
      : { [usd.model]: expected.usdCounter, [eur.model]: expected.eurCounter },
    services: otherVault ? { [usd.service]: expected.usdCounter }
      : { [usd.service]: expected.usdCounter, [eur.service]: expected.eurCounter },
  };
}
function expectUnrecorded(reply: WireReply<UsageRecordResult | UsageApiError>, source: UsageSource) {
  expect(reply.status).toBe(200);
  expect(reply.body).toEqual({ recorded: false, replayed: false, source, cost: null, vaultRollup: null });
}

/* MODELS-01 Independent model slots and role bindings should work.
 * Canon: ARCH-0036 #inference-slots, #model-line, #roles; OF-126/129/131/132/133/134/138.
 * Preserve ModelManifest {version:2, routes:{llm,embedder,oneironer},
 * roles:{[role]:{model,slot,tier,route_models?}}, verdict?}. Invoke the LLM,
 * retrieval_embedder, extraction_encoder and alternate generative role on
 * separate provider origins; replace only generative_reasoner and inspect
 * each call's pinned identity/revision and route. Fixture: scenarios.json.
 * [models.roles.*] configures seats, but there is no typed public manifest
 * read/replace or slot-route mutation in the HTTP/SDK catalog. Raw /v1/llm
 * names a model, not a role, so it cannot stand in for this contract.
 */
suite.todo(test, "MODELS-01", "waits on typed model-manifest and independent slot-route read/replace calls with role receipts");

/* MODELS-02 Typed multimodal streaming should work.
 * Canon: ARCH-0036 #model-line, ARCH-0026 #run-tree; OF-126/136.
 * ContentPart is tagged by kind; LlmStreamEvent is tagged by event. Preserve
 * {event:"text_delta"|"reasoning_delta",part_id,text}, image start/delta/end,
 * and Done {message:{role,content:ContentPart[]},usage,finish_reason}.
 * Subscribe HTTP+WS before one generation, correlate interleaved part IDs,
 * detach only the slow subscriber at the fixture barrier, and reopen the
 * one durable terminal after restart. Audio is input evidence, not an
 * invented audio_* stream event. scenarios.json pins every part and usage.
 * Current chat emits text-only ChatLine deltas and has no typed attach to
 * the same producer; two raw /v1/llm/stream POSTs would make two producers.
 */
suite.todo(test, "MODELS-02", "waits on typed shared model-stream subscribe/detach and durable ContentPart terminal read over HTTP and WS");

/* MODELS-03 One retry authority and explicit failure should work.
 * Canon: ARCH-0026 #run-tree, ARCH-0036 #model-line; OF-130/140.
 * The typed outcome distinguishes Retryable, Fatal and BudgetDenied; the
 * durable step retains Started/ResponseReceived/Logged/Finished checkpoints.
 * scenarios.json declares 503->success (2 attempts), 3 exhausted attempts,
 * and fatal with/without a declared deterministic non-model fallback.
 * Assert exact external call counts and typed nonempty terminal failures.
 * Offer fallback within one call is not a second durable retry authority.
 * A raw request has no durable step identity, retry policy or fallback DTO;
 * private call_as_step is not a public submission or receipt door.
 */
suite.todo(test, "MODELS-03", "waits on typed durable model-step submission with declared retries, deterministic fallback and inspectable step receipt");

/* MODELS-04 Structured output retries and refusal should work.
 * Canon: ARCH-0036 #model-line, runtime #mint:S4; OF-436.
 * Request ResponseFormat {format:"json",schema}; result is schema-valid
 * {count:2} or typed validation exhaustion, not untyped best-effort text.
 * scenarios.json pins native (1), invalid->valid shim (2), and exhaustion
 * (3 total) attempts. Schema feedback must reach the corrective request.
 * The internal schema shim exists. Neither the HTTP/SDK catalog nor MCP
 * exposes this one-shot engine step. ai.verdict's choice/score question is
 * not an arbitrary JSON-schema request; agent REPL correction is exempt.
 */
suite.todo(test, "MODELS-04", "waits on typed one-shot Json{schema} model-step request/result over HTTP and MCP");

/* MODELS-05 Budget reserve settle and cached resume should work.
 * Canon: ARCH-0026 #run-tree, runtime #charge-rule; OF-076/127/286/290/319.
 * Preserve reserve->lease->settle: an authorized in-flight call can finish,
 * a settled logical step returns its cached terminal on resume, and usage
 * settles once. A no-usage answer pays its reservation; every failed rung
 * that went out pays its own reservation, even when all rungs fail.
 * scenarios.json pins monetary amounts, concurrency barrier and call count.
 * Restart only after a public settled receipt, not provider arrival alone.
 * The raw process-lifetime token meter and manual /v1/usage/events records
 * cannot substitute for a persisted monetary lease or durable-step resume.
 */
suite.todo(test, "MODELS-05", "waits on typed persisted monetary run lease and durable model-step resume with per-rung settlement receipts");

/* MODELS-06 Graceful budget wrap and hold should work.
 * Canon: ARCH-0079 #work/#budget, ARCH-0026 #run-tree; OF-271/419/496/532.
 * Budget read/notice must expose remaining allowance, PLAN/LAND pressure,
 * checkpoint and partial results. The fixture declares a 10% landing
 * reserve; ordinary work cannot spend it. Top up the held lease and resume
 * the same model and work, never silently choose a cheaper one. A soft
 * share is not a pinned cap, and a hold is neither Done nor abandonment.
 * scenarios.json preserves the fixture policy and expected money facts.
 * Generic run-tree intervene and fanout approval do not expose self.budget,
 * its steering notice, or an owned lease's top-up/resume contract.
 */
suite.todo(test, "MODELS-06", "waits on typed agent budget read/notice and persisted landing hold, top-up and resume over HTTP and MCP");

suite.test(test, "MODELS-07", "Inference mode and usage attribution should work", async () => {
  const catalog = await loadFixtures();
  const facts = await catalog.readJson<UsageFacts>("models-usage");
  const tableBytes = await catalog.readArchive("models-price-table");
  const publicKey = await catalog.readArchive("models-price-table-public-key");
  const signature = await catalog.readArchive("models-price-table-signature");
  // This signs the external fixture oracle, not an invented server request
  // field. POST /v1/usage/events accepts costRates plus priceTableSnapshot.
  expect(verify(null, tableBytes, Buffer.from(publicKey), signature)).toBe(true);
  const table = JSON.parse(new TextDecoder().decode(tableBytes)) as PriceTable;
  const [usdFixture, eurFixture] = facts.events;
  const usd = usageEvent(facts, usdFixture, table);
  const eur = usageEvent(facts, eurFixture, table);
  const otherVault = { ...usd, vaultId: facts.otherVaultId };
  const changedFacts: UsageEvent[] = [
    { ...usd, tokenCounts: { ...usd.tokenCounts, inputTokens: 1001 } },
    { ...usd, model: "models-fixture/other@rev-c" },
    { ...usd, service: "models-fixture-other-service" },
    { ...usd, costRates: { ...usd.costRates, priceTableSnapshot: "models-fixture-prices-v2" } },
    { ...usd, costRates: { ...usd.costRates, currency: "EUR" } },
    { ...usd, serviceAmount: 625001 },
  ];
  const observations = [];
  // Three fresh real vault processes, sequential in this one-slot file. No
  // inference/key is needed to submit externally authored usage facts.
  for (const mode of facts.modes) {
    const engine = await EngineFixture.start({
      id: `MODELS-07-${mode.configMode}`, profile,
      serverConfig: `[runtime]\nmode = "${mode.configMode}"\n`,
    });
    try {
      await engine.requireHttpDoor("/v1/usage/events", "POST");
      await engine.requireHttpDoor("/v1/usage/owners/{owner}/vaults/{vault_id}/rollup", "GET");
      const first = await submitUsage(engine.client, usd);
      const replay = await submitUsage(engine.client, usd);
      const conflicts = [];
      for (const changed of changedFacts) conflicts.push(await submitUsage(engine.client, changed));
      const second = await submitUsage(engine.client, eur);
      const separate = await submitUsage(engine.client, otherVault);
      const rollup = await readUsage(engine.client, facts.owner, facts.vaultId);
      const otherRollup = await readUsage(engine.client, facts.owner, facts.otherVaultId);
      const absent = await readUsage(engine.client, facts.owner, "models-fixture-vault-empty");
      // Attribution comes from host configuration, not a caller's source label.
      const forgedSource = await submitUsage(engine.client, {
        ...usd, idempotencyKey: "models-source-label-probe", source: "oneiron_cloud",
        vaultId: "models-fixture-source-probe",
      });
      const sourceRollup = await readUsage(engine.client, facts.owner, "models-fixture-source-probe");
      if (mode.recordsBillingFacts) await engine.restart();
      const afterRestart = await submitUsage(engine.client, usd);
      const finalRollup = await readUsage(engine.client, facts.owner, facts.vaultId);
      const seen = { mode, first, replay, conflicts, second, separate, rollup, otherRollup,
        absent, forgedSource, sourceRollup, afterRestart, finalRollup };
      await engine.artifacts.json("usage-observations.json", seen);
      observations.push(seen);
    } finally {
      await engine.close();
    }
  }
  // Collect all modes before assertions: a Local/BYO regression must not
  // prevent the hosted sequence from reaching its idempotency/isolation checks.
  for (const seen of observations) {
    const { mode } = seen;
    expect(seen.absent.status).toBe(404);
    if (!mode.recordsBillingFacts) {
      for (const reply of [seen.first, seen.replay, seen.second, seen.separate,
        seen.afterRestart, seen.forgedSource, ...seen.conflicts]) expectUnrecorded(reply, mode.source);
      for (const reply of [seen.rollup, seen.otherRollup, seen.sourceRollup, seen.finalRollup]) {
        expect(reply.status).toBe(facts.expected.unmeteredRollupStatus);
        expect(reply.body).toMatchObject({ code: "NOT_FOUND" });
      }
      continue;
    }
    expect(seen.first.status).toBe(200);
    expect(seen.first.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[0] });
    expect(seen.second.status).toBe(200);
    expect(seen.second.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[1], vaultRollup: expectedRollup(facts) });
    for (const reply of [seen.replay, seen.afterRestart]) {
      expect(reply.status).toBe(200);
      expect(reply.body).toMatchObject({ recorded: false, replayed: true,
        source: mode.source, cost: facts.expected.costs[0] });
    }
    for (const reply of seen.conflicts) {
      expect(reply.status).toBe(409);
      expect(reply.body).toMatchObject({ code: facts.expected.conflictCode,
        details: { code: facts.expected.conflictCode } });
    }
    expect(seen.separate.status).toBe(200);
    expect(seen.separate.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[0], vaultRollup: expectedRollup(facts, true) });
    for (const reply of [seen.rollup, seen.finalRollup]) {
      expect(reply.status).toBe(200);
      expect(reply.body).toEqual(expectedRollup(facts));
    }
    expect(seen.otherRollup.status).toBe(200);
    expect(seen.otherRollup.body).toEqual(expectedRollup(facts, true));
    expect(seen.forgedSource.status).toBe(200);
    expect(seen.forgedSource.body).toMatchObject({ source: mode.source,
      recorded: true, replayed: false, cost: facts.expected.costs[0] });
    expect(seen.sourceRollup.status).toBe(200);
    expect(seen.sourceRollup.body).toEqual({ ...expectedRollup(facts, true),
      vaultId: "models-fixture-source-probe" });
  }
}, 60_000);

/* MODELS-08 Official subscription login boundary should work.
 * Canon: ARCH-0036 #model-line, ARCH-0069 #handles; OF-137/375.
 * A seat has vendor/account/machine/login-store/plan-window metadata, never
 * credential bytes in a model result or control-plane transfer. Complete
 * official login at a loopback fixture issuer, call the seat, exhaust its
 * window, inspect the typed wait/reset and declared fallback choices, then
 * logout and prove the old seat no longer works. A configured paid fallback
 * is permitted; login alone permits none. scenarios.json pins the boundary.
 * `seat login-plan` only prints the plan; it has no callback/token exchange
 * or logout. No real vendor credential, scraped store or client identity
 * may be used as a substitute for this missing official public login flow.
 */
suite.todo(test, "MODELS-08", "waits on documented official subscription login/callback/logout and typed credential-free seat status with configurable issuer");

/* MODELS-09 Model registry offers are evidence not permission should work.
 * Canon: ARCH-0036 #model-line, ARCH-0003 #learning; OF-512.
 * Preserve offer=model@where, pinned catalog revision/cost/score evidence,
 * owned held-out labels and a proposed role binding. Refresh/diff, nominate,
 * trial, inspect the proposal, deny it, then call the original role again.
 * The proposal receipt must cite revision and real trial cost; external
 * ranks cannot grant authority. scenarios.json pins both catalog revisions,
 * independent labels and unchanged incumbent binding after denial.
 * ai.options lists current offers. Generic pack/learning-setting mutations
 * are not typed catalog refresh/trial/model-binding approval operations.
 */
suite.todo(test, "MODELS-09", "waits on typed model catalog refresh/diff, held-out trial and proposed role-binding approval/denial calls");
