import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, ownResource } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Canon, row coverage, authored inputs and per-ID assertions: retrieval-scenarios.
 * Executable vector oracle: retrieval-evidence. Neither contains engine output.
 * Bindings read from the generated @oneiron/client catalog, server OpenAPI DTOs,
 * public CLI and Oneiron SDK. The relevant public files have no diff between
 * this worktree's ea42ef0c7 and origin/main 6f2446660 (source-only readback).
 *
 * G01: an absent typed door is a BLOCKED suite.todo, never a generic callVerb,
 * execute_code, engine import or raw storage seed. Existing public endpoints
 * are not claimed missing just because a complete planned flow is blocked.
 * Activation notes below retain the canon contract without inventing URLs or
 * wire DTOs where canon/main has not defined them. A TODO is not partial PASS.
 *
 * Fresh authenticated EngineFixture per runnable flow. One slot, normal 30s
 * harness flow budget, no private clock, no mutation retry, no model downloads.
 * No engine constants or default settings are changed. The four-dimensional
 * vectors, token ceiling and corpus times are fixture inputs, not benchmarks.
 */

type ReadReceipt = FacadeResult<"vault.claims.list">["narrowing"];
type ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
interface Probe { readonly query: string; readonly vector: number[] }
interface EvidenceClaim {
  readonly label: string;
  readonly predicate: string;
  readonly value: string;
  readonly vector: number[];
}
interface EvidenceFixture {
  readonly embedder: {
    readonly modelKey: string; readonly modelId: string; readonly dimensions: number;
    readonly probeText: string; readonly probeVector: number[]; readonly usageInputTokens: number;
  };
  readonly confidence: number; readonly salience: number;
  readonly occurredAt: number; readonly learnedAt: number;
  readonly claims: EvidenceClaim[];
  readonly weak: Probe;
  readonly anomalous: (Probe & { readonly label: string })[];
  readonly strong: Probe & { readonly requiredLabels: string[] };
  readonly expectations: {
    readonly storedSource: string; readonly storedApproval: string;
    readonly storedLifecycle: string; readonly storedStale: boolean;
  };
  readonly constants: { readonly tokenBudget: number; readonly resultLimit: number };
}

// Subsets of the existing OpenAPI CoreContextPackRequest/Response and search
// response DTOs. These add no field, verb or interpretation of an opaque body.
interface ContextPackRequest {
  readonly query: string; readonly query_vector: number[];
  readonly limit: number; readonly edge_hop: number; readonly view: "full";
  readonly budget: { readonly token_budget: number };
}
interface ContextPackReply {
  readonly results: { readonly id: string }[];
  readonly neighbors: { readonly id: string }[];
  readonly state: {
    readonly kind: "ok" | "missing_data" | "low_confidence" | "skipped";
    readonly reason?: string;
  };
  readonly evidence: { readonly result_ids: string[]; readonly scores: unknown[] };
  readonly narrowing: ReadReceipt;
}
interface VectorPage {
  readonly items: { readonly id: string; readonly score: number }[];
  readonly narrowing: ReadReceipt[];
}

/** External OpenAI-compatible embedder only; it never reads or fakes a vault.
 * Shared ScriptedProviders has ordered replies, but no exact text-table lookup
 * for the reconciler's variable batches. This fixture accepts ONLY canon's
 * `${predicate}: ${valueText}` and the documented startup probe. Unknown input
 * fails the flow; no default vector, prompt echo or engine-derived answer.
 */
function startVectorTable(fixture: EvidenceFixture) {
  const vectors = new Map<string, number[]>([
    [fixture.embedder.probeText, fixture.embedder.probeVector],
    ...fixture.claims.map(row => [`${row.predicate}: ${row.value}`, row.vector] as [string, number[]]),
  ]);
  const seen = new Set<string>();
  const violations: string[] = [];
  let closed = false;
  let disown = () => {};
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      try {
        if (request.method === "GET" && path === "/v1/models") {
          return Response.json({ object: "list", data: [{ id: fixture.embedder.modelKey, object: "model" }] });
        }
        if (request.method !== "POST" || path !== "/v1/embeddings") {
          throw new Error(`Unexpected vector fixture route: ${request.method} ${path}`);
        }
        const body = await request.json() as { model?: unknown; input?: unknown };
        if (body.model !== fixture.embedder.modelKey || !Array.isArray(body.input) || body.input.length === 0) {
          throw new Error("Vector fixture needs its declared model and a nonempty input array");
        }
        const data = body.input.map((text: unknown, index: number) => {
          if (typeof text !== "string" || !vectors.has(text)) {
            throw new Error("Unexpected canonical text sent to vector fixture");
          }
          seen.add(text);
          return { object: "embedding", index, embedding: vectors.get(text)! };
        });
        return Response.json({ object: "list", model: fixture.embedder.modelKey, data,
          usage: { prompt_tokens: fixture.embedder.usageInputTokens, total_tokens: fixture.embedder.usageInputTokens } });
      } catch (error) {
        violations.push(error instanceof Error ? error.message : String(error));
        return Response.json({ error: { type: "invalid_request_error", message: "Vector fixture request refused" } }, { status: 400 });
      }
    },
  });
  const close = async () => {
    if (closed) return;
    closed = true;
    disown();
    await server.stop(true);
    if (violations.length) throw new Error(violations.join("; "));
  };
  disown = ownResource(close);
  return { endpoint: `http://127.0.0.1:${server.port}/v1`, seen, close };
}

/* RETRIEVAL-01 — Five-channel recall and stable rank should work.
 * OF-081/094/098/100/102; ARCH-0004 #rrf-pipeline.
 * Canon: search_vector, search_text, search_ppr(seeds), search_temporal and
 * search_phonetic(codes) feed one deterministic rank. Trace must identify each
 * channel's contribution. A fixed learned-weight vector, fixed query time and
 * identical public inputs must repeat the same item order; no score formula
 * is copied. Assert every hand-labeled relevant fixture and all-evidence before
 * unrelated, then the complete repeated order and trace component membership.
 *
 * Current RecallRequest = { query, effort?, scope?, limit?, as_of?, deadline_ms?,
 * media?, query_affect?, format? } -> MemoryPack { items, retrieval_meta,
 * scope_honesty, narrowing, ... }. as_of resolves time words, not a fake clock.
 * POST /v1/core/context-pack already has evidence.scores with components
 * {signal, rank, score}; vault.explain.memory already reads score evidence.
 * Neither RecallRequest nor CoreContextPackRequest accepts caller PPR seeds
 * or phonetic codes, or a pinned blend/replay input. Do not call a Rust builder
 * or invent a /trace endpoint. Populate the fixture only by public writes.
 */
suite.todo(test, "RETRIEVAL-01", "waits on typed five-channel query inputs for phonetic codes/PPR seeds and fixed-rank trace replay");

/* RETRIEVAL-02 — Multilingual lexical retrieval should work.
 * OF-097/098/100/101; ARCH-0004 #rrf-pipeline.
 * WitnessTurn {conversation_ref, messages: WitnessMessage[], occurred_at} ->
 * WitnessReceipt; vault.search.bm25({query,limit}) and GET /api/search/text
 * already support lexical search. Witness the exact EN/JA/ZH fixture strings,
 * assert the authored exact/morphological matches, then resolve original text
 * and citation revisions without normalizing the saved text.
 * Canon's phonetic match must also recover Cuomo -> クオモ and Rupert -> Robert
 * with no lexical coincidence. Main now generates name codes on write (v1
 * kana/romaji and English Soundex); that producer is NOT claimed absent.
 * The server recall door still supplies no phonetic query codes, and current
 * HTTP/SDK request DTOs have no such input. Preserve the full test as blocked,
 * not a passing lexical-only substitute. NPD/learned ladder quality is not
 * asserted by the deterministic provider profile.
 */
suite.todo(test, "RETRIEVAL-02", "waits on typed HTTP/SDK phonetic query input for cross-script and misheard names");

/* RETRIEVAL-03 — Bitemporal widening should work.
 * OF-081; ARCH-0004 #temporal-variants/#temporal-bound.
 * Canon typed operations:
 *   search_temporal_with_sigma(start,end,sigma_secs,anchor_mode,limit)
 *   search_temporal_bitemporal(occurred_s,occurred_e,learned_s,learned_e,sigma,limit)
 *   temporal_adaptive(true); maximum three widening rounds.
 * Insert late-event, early-event, nearby-event in the fixture's deliberately
 * different ingestion order, using ClaimInput occurred_at/learned_at. Read
 * each axis narrowly, widen only within the declared outer window, and check
 * authored occurrence/learning matches and dates, never ingestion sequence.
 * Current context-pack time {since?,occurred_start?,occurred_end?,learned_start?,
 * learned_end?} is filtering, not this anchor/sigma/adaptive request. Recall
 * as_of is only the reference for time words; max effort's internal bitemporal
 * selection is not caller control or widening evidence. No synthetic time API.
 */
suite.todo(test, "RETRIEVAL-03", "waits on typed bitemporal anchor, sigma and adaptive-widening controls/results");

/* RETRIEVAL-04 — Read clamp across every public read door should work.
 * OF-064/065/086/111; ARCH-0004 #access and ARCH-0043 #guest-grants.
 * Canon Claim: approvalStatus auto|approved, lifecycleStatus active, stale
 * false, not erased/contaminated. Both endpoints must be readable. World
 * sections stay labeled. Requested filters meet the credential ceiling.
 * ScopedReadResult<T> = {value:T,narrowing:{requested,actor_ceiling,applied,
 * narrowed_axes,suppressed_count,replan_hint}}. Every executed/narrowed read
 * must retain its receipt; a withheld world yields no names or count oracle.
 *
 * Pair an existing non-owner reader publicly, create the fixture eligibility
 * matrix and readable -> private edge, then exercise the HTTP/MCP recall,
 * point, hydrate, query, batch-short-id hydrate, search and neighbor doors in
 * retrieval-scenarios. Check exact eligible labels, no private endpoints or
 * stale/proposed/deleted claims, and that added filters only remove results.
 * These read doors/receipts already exist. ClaimInput has no source-frontier
 * or stale field, so a raw claim body through vault.batch is NOT a lawful
 * substitute for a typed stale producer. ReadScope describes a receipt;
 * current read requests do not expose its full requested-filter controls.
 */
suite.todo(test, "RETRIEVAL-04", "waits on typed stale-claim fixture producer and caller read-filter controls across read doors");

/* RETRIEVAL-05 — Retrieval effort and deadline should work.
 * OF-084/109/228; ARCH-0004 #effort/#rerank-built.
 * Current vault.recall({query,effort,deadline_ms?,limit?}) -> MemoryPack.
 * All five levels and the 1..60000ms deadline already exist; call is the live
 * mode. RerankReport is {status:"applied",model,candidates,calls,...} or
 * {status:"skipped",reason:"no_reranker"|"no_candidates"|"deadline"|"device_only"}.
 * Configure only the documented [models.roles.reranker] and loopback provider;
 * light/medium must take no model lease, high tiers use only configured paid
 * stages, and unconfigured reranking must explain itself. Capture receipts.
 *
 * The complete flow also holds a HyDE/expansion response, asks with the fixture
 * deadline while held, asserts best admitted evidence/partial and no invented
 * late facts, releases it, and checks delivered bytes and stored claims remain
 * unchanged. Canon's host-injected HydeExpander has no typed HTTP/SDK host
 * binding/completion door here. ConsolidationEnqueueRequest.input:unknown and
 * a private slow-stage hook are not substitutes. A delayed reranker alone
 * does not prove the plan's delayed expansion behavior.
 */
suite.todo(test, "RETRIEVAL-05", "waits on typed host HyDE/expansion configuration with a public completion receipt");

/* RETRIEVAL-06 — Evidence abstention not invented recall should work.
 * OF-085/104/090; ARCH-0004 #pre-assembly/#evidence-floors-endpoint.
 * Generic endpoint profile, explicit fixture vectors, no generator/HyDE role.
 * Weak vectors are near-orthogonal to the weak probe. The two strong vectors
 * are almost parallel, so a tiny gap alone must not reject them. Anomalous
 * control bytes/repetition withhold evidence, not saved facts. Empty packs
 * must explain themselves with typed state, never silently look successful.
 */
suite.test(test, "RETRIEVAL-06", "Evidence abstention not invented recall should work", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<EvidenceFixture>("retrieval-evidence");
  const provider = startVectorTable(fixture);
  const engine = await EngineFixture.start({ id: "RETRIEVAL-06", profile,
    embedder: { endpoint: provider.endpoint, modelKey: fixture.embedder.modelKey,
      modelId: fixture.embedder.modelId, dimensions: fixture.embedder.dimensions,
      egress: { allowAll: true } } });
  try {
    await engine.requireHttpDoor("/v1/core/context-pack", "POST");
    await engine.requireHttpDoor("/api/search/vector", "GET");
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const identities = new Map<string, { id: string; ref: string }>();
    for (const row of fixture.claims) {
      const input: FacadeInput<"vault.claims.upsert"> = {
        scope,
        predicate: row.predicate, subject_ref: engine.pairedActor.principalRef,
        value: row.value, confidence: fixture.confidence,
        source: fixture.expectations.storedSource, salience: fixture.salience,
        occurred_at: fixture.occurredAt, learned_at: fixture.learnedAt,
      };
      const receipt = await engine.client.call("vault.claims.upsert", input);
      expect(receipt.approval).toBe(fixture.expectations.storedApproval);
      await engine.awaitReceipt(receipt.receipt_ref);
      const read = await engine.client.call("vault.hydrate", { refs: [receipt.claim_short_id] });
      expect(read.value).toHaveLength(1);
      const entity = read.value[0]!;
      expect(entity.occurred_start).toBe(fixture.occurredAt);
      expect(entity.occurred_end).toBe(fixture.occurredAt);
      expect(entity.learned_at).toBe(fixture.learnedAt);
      identities.set(row.label, { id: entity.id_hex, ref: receipt.claim_short_id });
    }

    // Observe each row through its own positive public probe. A provider
    // request alone does not prove its fill was admitted/persisted, and weak
    // rows need not survive a different probe's evidence floor.
    for (const row of fixture.claims) {
      const params = new URLSearchParams({ query: row.vector.join(","),
        limit: "1", view: "standard", countMode: "none" });
      await awaitPublic(async () => (await engine.client.request<VectorPage>("GET", `/api/search/vector?${params}`)).body,
        page => page.items.some(hit => hit.id === identities.get(row.label)!.id),
        { label: `fixture embedding visible through public vector search: ${row.label}` });
      expect(provider.seen.has(`${row.predicate}: ${row.value}`)).toBe(true);
    }

    const filter: FacadeInput<"vault.claims.list"> = { subject_ref: engine.pairedActor.principalRef, limit: 1000 };
    const before = await engine.client.call("vault.claims.list", filter);
    for (const row of fixture.claims) {
      const matching = before.value.filter(claim => claim.predicate === row.predicate);
      expect(matching).toHaveLength(1);
      expect(matching[0]).toMatchObject({ value: row.value, confidence: fixture.confidence,
        source: fixture.expectations.storedSource, approval: fixture.expectations.storedApproval,
        lifecycle: fixture.expectations.storedLifecycle, stale: fixture.expectations.storedStale });
    }

    const requestPack = async (probe: Probe): Promise<ContextPackReply> => {
      const request: ContextPackRequest = { query: probe.query, query_vector: probe.vector,
        limit: fixture.constants.resultLimit, edge_hop: 0, view: "full",
        budget: { token_budget: fixture.constants.tokenBudget } };
      return (await engine.client.request<ContextPackReply>("POST", "/v1/core/context-pack", request)).body;
    };
    const observed: { label: string; state: ContextPackReply["state"]; ids: string[] }[] = [];
    for (const probe of [{ ...fixture.weak, label: "weak-no-keywords" }, ...fixture.anomalous]) {
      // A positive weak-evidence check needs to prove the lexical channel
      // cannot rescue it; a bare empty-vault or vector-only query is not it.
      const keywords = await engine.client.call("vault.search.bm25", { query: probe.query, limit: 10 });
      expect(keywords.value).toEqual([]);
      const pack = await requestPack(probe);
      expect(pack.results).toEqual([]);
      expect(pack.neighbors).toEqual([]);
      expect(["missing_data", "low_confidence"]).toContain(pack.state.kind);
      expect(typeof pack.state.reason).toBe("string");
      expect(pack.state.reason!.length).toBeGreaterThan(0);
      expect(pack.evidence.result_ids).toEqual([]);
      expect(pack.evidence.scores).toEqual([]);
      observed.push({ label: probe.label, state: pack.state, ids: [] });
    }
    const strongKeywords = await engine.client.call("vault.search.bm25", { query: fixture.strong.query, limit: 10 });
    expect(strongKeywords.value).toEqual([]);
    const strong = await requestPack(fixture.strong);
    expect(strong.state.kind).toBe("ok");
    const requiredIds = fixture.strong.requiredLabels.map(label => identities.get(label)!.id).sort();
    expect(strong.results.slice(0, requiredIds.length).map(row => row.id).sort()).toEqual(requiredIds);
    expect(strong.results.every(hit => [...identities.values()].some(row => row.id === hit.id))).toBe(true);
    observed.push({ label: "strong-near-tie", state: strong.state, ids: strong.results.map(row => row.id) });

    // Independent expected bodies above, plus the read-only invariant over
    // all owner claims, including any bootstrap rows (not just these four).
    const after = await engine.client.call("vault.claims.list", filter);
    const byRef = (a: ClaimRow, b: ClaimRow) => a.claim_ref.localeCompare(b.claim_ref);
    expect([...after.value].sort(byRef)).toEqual([...before.value].sort(byRef));
    for (const row of fixture.claims) {
      const read = await engine.client.call("vault.hydrate", { refs: [identities.get(row.label)!.ref] });
      expect(read.value).toHaveLength(1);
      expect(read.value[0]).toMatchObject({ occurred_start: fixture.occurredAt,
        occurred_end: fixture.occurredAt, learned_at: fixture.learnedAt });
    }
    await engine.artifacts.json("retrieval-evidence.json", { fixtureId: "retrieval-evidence", observed });
  } finally {
    await engine.close();
    await provider.close();
  }
});

/* RETRIEVAL-07 — Freshness does not rewrite confidence should work.
 * OF-095/099; ARCH-0003 #claim-type, ARCH-0004 #rrf-pipeline/#aging-curve-ruling.
 * Canon Claim.confidence is truth confidence; memoryClass is predicate/class
 * metadata (semantic/working/etc.), not a free new top-level entity kind.
 * Exponential aging stays; Weibull and its mass A/B run are NOT requirements.
 * Write old/new facts with the fixture's equal confidence and declared classes.
 * At supported rank-time anchors inspect evidence and stored bodies; allow
 * availability/rank changes but require confidence bit-for-bit unchanged.
 * Upsert a replacement through the ordinary gate, check superseded_short_id,
 * absent old fact in current recall and both bodies/confidences in history.
 *
 * ClaimInput {occurred_at,learned_at,valid_from,valid_to,confidence,...},
 * vault.claims.history({claim_ref}) -> ScopedReadResult<ClaimView[]> and
 * upsert's supersession receipts already exist. The missing inputs are typed
 * class-aging profile setup/readback and rank-time control. RecallRequest.as_of
 * resolves words like yesterday, NOT an aging clock or historical read. Do not
 * claim a rank-at-time experiment by merely supplying it or invent scope keys.
 */
suite.todo(test, "RETRIEVAL-07", "waits on typed class-aging profile setup/readback and fixed-time rank control");

/* RETRIEVAL-08 — Warm and rebuilt graph parity should work.
 * OF-087/103/447; ARCH-0019 #storage-invariants, ARCH-0004 #cache-seeding.
 * Canon requires heavy structures to drop in-process and rebuild lazily. PPR
 * cache key includes seeds/depth/alpha/formula/weighting; no residual/frontier
 * payload or speed assertion is required for parity.
 * Write the fixture graph through public structural puts, establish grants,
 * and assert the known authorized neighborhood and fixed-input answer across
 * cold, warm, completed SLIM/drop, and resume. Compare evidence and order, not
 * cache metadata, timings or scores. The withheld node must never surface.
 * Current CLI has serve/reembed/maintain, but no typed SLIM/drop-heavy/resume
 * command and completion receipt. EngineFixture.restart() kills the process;
 * it is not this in-process drop. No Rust slim calls or process-signal proxy.
 */
suite.todo(test, "RETRIEVAL-08", "waits on public CLI SLIM/drop-heavy and resume with completion receipts");

/* RETRIEVAL-09 — Optional affect and community priors should work.
 * OF-029/032/110/423/563; ARCH-0004 #rrf-pipeline.
 * Canon query affect is {valence:-1..1,arousal:0..1,dominance:0..1}; semantic
 * edges have VAD, but authority/confidence remain separate. Weights start at
 * zero; enable affect, arousal and community separately, assert the authored
 * favored candidate/trace while never returning private-community, then turn
 * each off and recover baseline semantics. Confidence and approval never move.
 * Current RecallRequest.query_affect and CoreContextPackRequest.query_affect
 * already exist. Neither is a weight or a grant. StructuralEdgeSpec exposes
 * {edge_kind,target_ref,weight?}, not a typed VAD/source-evidence producer;
 * the public request/config catalog does not bind all three manifest weights
 * with readback. Unknown JSON in a policy or pack call is not a typed binding.
 */
suite.todo(test, "RETRIEVAL-09", "waits on typed affect/arousal/community weight controls and VAD evidence setup");

/* RETRIEVAL-10 — Clustering produces proposals not truth should work.
 * OF-089; ARCH-0004 #rrf-pipeline, ARCH-0040 #mcp-actor-ceilings.
 * Canon groups by exact {subject,predicate,world}, then cosine cohesion;
 * output is candidate cohorts for judgment, never approved semantic claims.
 * Through tool-first MCP, request the two fixture clusters and ambiguous bridge,
 * inspect proposed structure and unchanged fact set, then choose merge/split
 * through its ordinary gate. Assert a refused proposal changes nothing and an
 * accepted verdict has a receipt; only accepted changes may affect recall.
 * The generated tool/SDK catalog has no typed clustering-proposal or cohort
 * settlement door. The pure Rust cluster functions are not an MCP tool. A
 * graph.ask question or made-up tool name would not qualify this operation.
 * No public request/result wire envelope is defined yet; do not invent one.
 */
suite.todo(test, "RETRIEVAL-10", "waits on typed MCP clustering proposal and gated merge/split settlement");

/* RETRIEVAL-11 — Visible claims are not automatically evidence should work.
 * OF-083; ARCH-0040 #memory-board-source-trust/#mcp-actor-ceilings.
 * Canon Claim source is user_stated|observed|inferred|generated|peer_stated|
 * imported|tool_output; approvalStatus and vetted evidence are separate axes.
 * Produce first-party Generated/Auto through its real host-stamped path, plus
 * unvetted foreign and pending critical rows, and a vetted positive control.
 * Recall for review may show Auto; a consolidation/effector proposal citing
 * those refs must exclude them as corroboration or authority. Check exact
 * output evidence refs/reasons, no outbound call before a valid gate, and no
 * new fact attributed to an ineligible source. The vetted control prevents a
 * vacuous assertion that a disabled/broken worker refused everything.
 * Current consolidation.enqueue {scope,input:unknown,run_id?,dedupe_key?,now?}
 * -> job ref and consolidation.status -> DreamerAttemptView describe a job,
 * not typed source candidates or evidence results. ClaimInput.source cannot
 * stand in for host-generated/vetted provenance. Wait for the typed producer,
 * proposal and evidence-result contracts; no generic input payload fallback.
 */
suite.todo(test, "RETRIEVAL-11", "waits on typed generated-claim vetting producer and consolidation/effector evidence results");

/* RETRIEVAL-12 — Vector prefix candidates get full-dimension refinement should work.
 * OF-088; ARCH-0004 #rrf-pipeline/#embedding-funnel.
 * Canon HNSW compatibility: {dimensions,fast_dims:Option<u16>}; full rows are
 * retained. Ordinary top-K prefix candidates are rescored in full dimensions;
 * speculative voice may explicitly skip that rescore and lower its limit.
 * Upload the fixture's literal four-dimensional vectors through a supported
 * door with a two-dimensional MRL prefix. Both prefixes are [1,0], but only
 * right-tail agrees with the full query [1,0,1,0]. Require right-tail before
 * wrong-tail on the ordinary path and full-dimension evidence/citations. On
 * the declared voice path require prefix-only evidence; do NOT pin tie order.
 * Current GET /api/search/vector takes query, limit, depth, queryText?,
 * deadlineMs?, space?, queryKind?, view?, countMode?. Its deadline/call effort
 * is not a voice skip-rescore flag. No typed public fast_dims setup or declared
 * prefix-only voice search/refinement evidence is bound. Endpoint embedding
 * can fill ordinary full rows (as RETRIEVAL-06 does), not create missing MRL
 * controls. No internal vector writes and no million-row performance claim.
 */
suite.todo(test, "RETRIEVAL-12", "waits on typed MRL fast_dims setup and voice prefix-only search with refinement evidence");
