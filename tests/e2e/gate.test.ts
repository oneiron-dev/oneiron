import { afterAll, expect, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, LIMITS } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Authority and consent, in plan order. Eight flows remain TODO; GATE-09 exercises the authorized write burst.
 * suite.todo registers real test.todo cases and mandatory BLOCKED report rows.
 * Do not turn a partial claim write or a schema lookup into passing coverage.
 *
 * Authored inputs and independent oracles: fixtures/gate/scenarios.json,
 * pinned by fixtures/gate/manifest.json. The runner verifies that fragment even
 * for TODO-only files. No fixture is a stored vault or a privileged log entry.
 *
 * Binding read: main 5ecd5af5bea2c70e25760f0583f276790f49fba4.
 * Inspected scripts/sdk/agent-verbs.json, packages/oneiron-client/src/{facade,
 * facade-types,index}.ts, server api/openapi_registry.rs, api/openapi/owner_paths.rs,
 * api/scoped_auth.rs, api/facade.rs, cli.rs and cli/owner_args.rs.
 *
 * Types below are CANON DESIGN NOTES, not new wire DTOs or client adapters.
 * Existing calls use generated FacadeInput/FacadeResult. For missing calls the
 * types name only canon's semantic arguments and observable results; final HTTP
 * paths and SDK methods must come from the typed catalog, never be guessed.
 * G01 forbids sending these through callVerb, raw entity bodies, execute_code,
 * vault.kv.put, a manifest disguised as a pack file, or a FacadeVerb cast.
 */
type Ref = string;
type GateApprovalCeiling = "Auto" | "Proposed";
type CanonSource = "user_stated" | "observed" | "inferred" | "generated"
  | "imported" | "tool_output" | "peer_stated";
type CanonCriticality = "normal" | "critical";
type CanonActorCeiling = {
  actor_class: string;
  actor_ref?: Ref;
  approval_ceiling: GateApprovalCeiling;
  read_capability?: "none" | "scoped";
  write_capability?: "none" | "per_op";
  parent_actor_ref?: Ref;
  grant_id?: Ref;
};
type CanonSourceTrust = Partial<Record<CanonSource, {
  max_auto_sensitivity?: number | "public" | "private" | "sensitive" | "restricted";
  receipted?: boolean;
  warned?: boolean;
  requires_explicit_auto_permit?: boolean;
}>>;
type CurrentClaimWrite = {
  request: FacadeInput<"vault.claims.upsert">;
  result: FacadeResult<"vault.claims.upsert">;
};
type CurrentPendingRead = {
  request: FacadeInput<"vault.writes.pending">;
  result: FacadeResult<"vault.writes.pending">;
};
type CurrentReceiptRead = {
  request: FacadeInput<"vault.receipts">;
  result: FacadeResult<"vault.receipts">;
};

// GATE-01 — Three-axis write decisions should work.
// ARCH-0040 #mcp-actor-ceilings / #memory-board-source-trust.
// Missing setup: owner-authored actor/source grant rows, including Generated's
// explicit auto permit. `token agent --tier` is real public CLI enrollment, but
// does not supply a typed policy/source-trust editing surface. Read-only is a
// capability, NOT a third approval-ceiling enum member.
// Existing HTTP: POST /v1/core/facade/vault.claims.upsert (ClaimInput -> CommitReceipt),
// vault.writes.pending (ReceiptsRequest -> PendingWrite[]), vault.receipts.
// Existing tool-first MCP: named vault.claims.upsert, arguments.spec = ClaimInput.
// Existing batch: vault.claims.seed takes CommitRequest {claims: ClaimInput[]}
// and returns CommitOutcome[] with per-leaf receipts/refusals, forced Proposed.
// That deliberate narrowing is allowed; no batch result may strengthen the meet.
// Do not use vault.batch's raw entity bodies as hand-built stored ClaimBody data.
// Typed waiting shape: ActorCeiling[] + SourceTrustMap + predicate-class rows ->
// receipted owner policy. The write/batch/read calls themselves already exist.
// Execute fixtures' identical ordinary/critical candidates across each carrier;
// compare each receipt and pending row with the authored meet table. A critical
// optimistic create can be Auto+pending-confirm: approval text alone is not proof
// it is confirmed. Forge actor/source/Auto in carrier metadata and read back the
// host-stamped author/source; reject or ignore escalation, never strengthen it.
type Gate01PolicyAxes = {
  actor_ceilings: CanonActorCeiling[];
  source_trust: CanonSourceTrust;
  rules: { predicate: string; criticality: CanonCriticality }[];
};
type Gate01ClaimBatch = {
  request: FacadeInput<"vault.claims.seed">;
  result: FacadeResult<"vault.claims.seed">;
};
suite.todo(test, "GATE-01", "waits on typed owner actor/source-grant policy editing for the three-axis write matrix");

// GATE-02 — Veto-only content checker should work.
// ARCH-0040 #content-check; ARCH-0036 #model-line. OF-037, OF-048.
// The real served AutoChecker exists: models.decisions.auto_check binds it and
// ai_host/dreamer.rs lends it to the promotion sink. It is NOT absent machinery.
// Missing: typed owner policy setup for the eligible automatic write and the
// enforced verdict-role row. A plain claim upsert or ai.verdict call does not
// prove that the WRITE door used the checker. Do not replace it with a fake gate.
// Waiting row shape from canon: {model slot, floor band, mode: shadow|enforce}.
// Verdict shape: schema -> typed value + calibrated confidence + basis bit.
// Via ScriptedProviders and real model adapters, script allow, below-band and
// vendor failure. Check Auto only for an already rule-permitted write; holds are
// Proposed. Replay the same intent: one durable effect, same policy/content cache
// identity, no silently retried mutation. An allow never gives a denied actor
// authority. Inspect pending state AND the gate/provider receipts, not prompt text.
type Gate02VerdictRole = {
  slot: Ref;
  floor: { low: number; high: number };
  mode: "shadow" | "enforce";
};
type Gate02Verdict =
  | { value: "allow" | "hold"; calibrated_confidence: number; basis: boolean }
  | { provider_failure: true };
suite.todo(test, "GATE-02", "waits on typed owner auto-permit policy and enforced content-verdict role setup");

// GATE-03 — Policy manifest defaults and owner control should work.
// DEC-0005 PolicyManifest; ARCH-0040 #mcp-actor-ceilings; identity #authority-log.
// CLI init/restart are public and available. No current named HTTP+SDK call
// reads/edits the Gate's PolicyManifest axes as an owner policy operation.
// vault.settings.learning and inference_defaults configure DIFFERENT policies.
// Typed waiting payload is PolicyManifest (pack_id, pack_version,
// min_engine_version, defaults, rules, actor_ceilings, source_trust, signatures,
// auto_checker), not a CLAIM containing manifest-looking JSON or a raw type-65 put.
// Inspect usable first-party defaults; owner tightens an actor and a source row;
// restart this vault; read the same restrictions and gate decisions. A second
// authorized restriction composes by meet, not newest-writer wins. Submit an
// untrusted replacement/widen (also a tighter contribution): it is a proposal,
// never a source of policy authority. A signature marker is not authentication.
// This follows the later 2026-09-27 canon amendment, not the registry's stale
// claim that arbitrary untrusted bytes may author tighter authoritative rows.
type Gate03ManifestSlice = Gate01PolicyAxes & {
  pack_id: string;
  pack_version: string;
  min_engine_version: string;
  defaults: { criticality?: CanonCriticality };
  auto_checker?: {
    generated_lens_static_analysis: "required";
    generated_claim_auto_permit: "explicit_only";
  };
};
suite.todo(test, "GATE-03", "waits on typed Gate PolicyManifest read/edit and untrusted policy-proposal calls");

// GATE-04 — Standing consent lifecycle should work.
// DEC-0006 #model, invariants 2-4; ARCH-0043 #guest-grants. OF-050/367/399.
// Typed semantic calls named by canon: approve_once(effect_digest),
// create_standing_grant(bound), and revoke(grant). Action bounds are disjoint
// from disclosure bounds: actor x class x envelope, not prose preferences.
// No current generic consent lifecycle HTTP+SDK call implements this trio.
// Connector-specific consent, room-join consent and self.grants.ask are not it.
// Allow once authorizes the exact asking fork's effect and is consumed once.
// The next distinct intent asks. Stop-asking deliberately creates a bounded
// LINEAGE grant, not one on a fork. Two in-envelope intents run without prompts;
// another project/audience or excess budget asks. Revoke; the next use asks.
// Read the registry and one settlement per ask, including word/grant references.
// Grants have NO stored expiry; a delegation slip's lifetime is another concept.
type Gate04ActionBound = {
  actor: Ref;
  class: string;
  envelope: { project: Ref; audience: Ref[]; budget: number };
};
type Gate04ApproveOnce = { effect_digest: string };
type Gate04CreateStandingGrant = { bound: Gate04ActionBound };
type Gate04Revoke = { grant: Ref };
suite.todo(test, "GATE-04", "waits on typed approve_once, create_standing_grant, grant registry and revoke calls");

// GATE-05 — Delegation attenuation and subtree revoke should work.
// ARCH-0040 mcp:11/mcp:13; identity #authority-log. OF-043/057/180/053.
// PairActor only pairs an already existing principal; it creates no delegation.
// token agent's independent owner mint is NOT delegation and cannot stand in.
// Waiting shape: child actor + live parent_actor_ref + narrowed read/action
// envelope -> child grant/slip; revoke parent grant -> append-only revoke receipt.
// Set up two children and a grandchild through that door; exercise each before
// revoke over HTTP and MCP. Wider requested reads/action budgets never exceed
// the parent's live meet. Revoke the PARENT ONLY; reuse the existing descendant
// credentials/connections, not newly paired ones. All lose subtree authority on
// their very next reads/writes. No per-child revoke and no timing sleep.
// Use the one shipped credential kind. Do not revive OF-180's conflicting
// separate ID-JAG token design or the human-delegate no-redelegation rule.
type Gate05DelegatedSlice = {
  actor_ref: Ref;
  parent_actor_ref: Ref;
  read: { projects: Ref[]; records: Ref[] };
  actions: { class: string; budget: number }[];
};
suite.todo(test, "GATE-05", "waits on typed attenuating agent delegation, parent-grant revoke and delegated read/action grant setup");

// GATE-06 — Catastrophe floor scoped bypass should work.
// DEC-0006 #bypass-grant; OF-465. This is not ordinary stop-asking.
// Waiting call: explicit OWNER create of a standing bypass bound to exactly one
// project OR one thread -> warning, grant receipt, typed bypass-active state.
// Five class names below are canon's classes, not a new action taxonomy.
// Self-grant as agent fails. Owner creates a project-A bypass. Covered acts in A
// can repeat without asks, each receipted as bypassed. Project B, a whole-vault
// target and any effect outside the bound still ask. In particular vault-wide
// destruction is outside a project bound; do not relabel it project-local.
// No bypass covers erase: an agent never erases or asks to erase; an owner still
// uses the separate manual preview/confirm. Another Owner's objection window is
// never skipped; inspect its pending state/deadline rather than waiting days.
// Current records.erase_preview/erase_confirm are real, but create no bypass.
type Gate06Catastrophe = "WidenOwnAuthority" | "KeyRecovery"
  | "VaultWideDestruction" | "SecurityControlDisable" | "MassSecretExport";
type Gate06BypassBound = {
  actor: Ref;
  classes: Gate06Catastrophe[];
  scope: { project: Ref } | { thread: Ref };
};
type Gate06ActiveState = { active: boolean; grant: Ref; bound: Gate06BypassBound };
suite.todo(test, "GATE-06", "waits on typed owner scoped bypass create/revoke, bypass-active state and bypassed effect receipts");

// GATE-07 — Review bundle accept and undo should work.
// ARCH-0032 #forks-proposals; ARCH-0040 #revert-run. G05 = preserve later work.
// Existing GET /v1/owner/runs[/review] and POST /runs/approve review a Dreamer
// gate bundle. They do NOT supply cross-kind revert_run or a revert handle.
// Waiting calls: accept proposal -> ProposalOutcome settlement; revert_run(run_id)
// or a selected subset -> compensating operations + per-change undo result.
// One run includes claims, edges, note revision and topology plus an external
// irreversible act. The written explainer cites its forks and is derived text,
// never another memory row. Check group verdict AND each change's verdict.
// Accept; add a later dependent edit. Undo an independent selected claim, then
// the remainder. Earlier receipts/history stay; compensations append. External
// effects stay one-way, deletes backup-only, and dependent work survives. The
// partial result lists EVERY non-undone change and why, not just a count.
// Individual Dreamer/conflict revert or artifacts.undo cannot stand in for this.
type Gate07Verdict = "landed" | "rejected" | "waiting" | "let_go";
type Gate07SettlementProjection = {
  kind: "ProposalOutcome";
  changes: { change: Ref; verdict: Gate07Verdict }[];
  verdict: Gate07Verdict;
  answered_by: { word_ref: Ref } | { row: string } | { grant: Ref };
  revert_handle: Ref;
};
type Gate07UndoProjection = {
  compensated: { change: Ref; receipt: Ref }[];
  not_undone: { change: Ref; reason: "one_way" | "backup_only" | "dependent" }[];
};
suite.todo(test, "GATE-07", "waits on typed cross-kind review settlement with revert handle and selective/full revert_run");

// GATE-08 — Critical confirmation and read floors should work.
// ARCH-0003 #claim-type/#criticality; OF-011/279. G07 = priority WITHIN budget.
// Current ClaimInput has confidence/salience, not a caller criticality override.
// POST /v1/core/context-pack already reports stats.critical_over_budget and
// stats.critical_count. Do not TODO those built fields or demand a budget bypass.
// Missing: a typed nonce/frontier-bound critical confirm HTTP+SDK ceremony for
// the generated candidate. An owner-authored replacement is a DIFFERENT write,
// and approving a run is not proof of this claim's fold-verified confirmation.
// Submit a low-confidence critical generated claim and many high-salience normal
// claims. Read pending state before/after unauthorized then owner confirmation.
// Criticality stays a predicate-class property; low confidence remains explicit
// as unverified, never faint/illegible. After confirmation critical items take
// priority. If criticals alone exceed the small pack budget, the budget remains
// hard and critical_over_budget warns with critical_count. Retracted/withheld
// claims remain excluded: criticality never overrules status or read authority.
type Gate08ConfirmArguments = {
  pending_operation: Ref;
  nonce: string;
  read_frontier_hash: string;
};
type Gate08PackStats = { critical_over_budget: boolean; critical_count: number };
suite.todo(test, "GATE-08", "waits on typed owner critical-claim confirmation ceremony and observable confirmation receipt");

// GATE-09 — No fixed burst refusal should work.
// ARCH-0044 #part-a/C5; ARCH-0040 #mcp-actor-ceilings. OF-294/487/520.
// The fixture's owner policy applies only after public subject setup. Keep every
// burst outcome, read every exact subject, and observe a real rule answer without
// manually answering the health question. The paired owner is a known granted
// actor; this fixture does not require an agent principal.
// These owner-HTTP shapes have no generated Facade equivalent. Sources:
// oneiron-server/src/wire_health.rs (HealthCheck, CheckState, AnsweredBy),
// wire_health/evidence.rs (crossing summary), and api/owner_routes/wire_health_routes.rs.
type Gate09NativeCrossed = { actors: string[]; verbs: string[] };
type Gate09NativeCrossing = {
  window: [number, number];
  seq: number;
  per_verb: number;
  per_actor: number;
  verbs: { verb: string; calls: number }[];
  actors: { actor: string; calls: number }[];
  crossed: Gate09NativeCrossed;
};
type Gate09NativeCheckState =
  | { state: "held" }
  | { state: "asked"; question: string; unit: string }
  | {
      state: "answered";
      answer: string;
      probability: number | null;
      by: unknown;
      at: number;
      question: string;
      unit: string;
    }
  | { state: "superseded"; by: string; question: string | null; unit: string | null };
type Gate09NativeHealthCheck = {
  subject: string;
  source: string;
  crossing: Gate09NativeCrossing;
  first_raised: number;
  last_raised: number;
  crossings: number;
  state: Gate09NativeCheckState;
  asked_in: string | null;
};
type Gate09NativeHealthList = { checks: Gate09NativeHealthCheck[] };
// Exact upsert wire key: METHOD plus MatchedPath.
// Source: api/facade.rs:3 (one route per verb at /v1/core/facade/<verb>),
// api/routes.rs:275-277 (nest at /v1/core/facade),
// wire_telemetry/http.rs:12-13 (verb is METHOD plus MatchedPath).
const GATE09_UPSERT_VERB = "POST /v1/core/facade/vault.claims.upsert";
function gate09IsBurst(
  check: Gate09NativeHealthCheck,
  baseline: Set<string>,
  ownerHex: string,
  upsertVerb: string,
): boolean {
  if (baseline.has(check.subject)) return false;
  if (check.source !== "wire") return false;
  return check.crossing.crossed.actors.includes(ownerHex) &&
    check.crossing.crossed.verbs.includes(upsertVerb);
}
function gate09IsRuleBy(by: unknown): boolean {
  // Native AnsweredBy::Ladder(DecisionRung::Rule) reads {"ladder":"rule"}
  // (wire_health.rs:83-85, model_decision/types.rs:11-12).
  if (typeof by !== "object" || by === null || Array.isArray(by)) return false;
  const record = by as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === 1 && record.ladder === "rule";
}
function gate09IsCoverBy(by: unknown): boolean {
  // Native AnsweredBy::Cover reads "cover" (wire_health.rs:88-91).
  return by === "cover";
}
function gate09IsDirectRuleValidBurst(check: Gate09NativeHealthCheck): boolean {
  // GrantRule Choice(valid_burst) probability Some(1.0) (wire_health.rs:271-279);
  // ask binds question.id.to_hex() and bound.unit.to_hex() (wire_health.rs:367);
  // EntityId::to_hex is 32-char lowercase hex (entity_id.rs). Presence only, no hex regex.
  const st = check.state;
  return st.state === "answered" &&
    st.answer === "valid_burst" &&
    gate09IsRuleBy(st.by) &&
    typeof st.question === "string" && st.question.length > 0 &&
    typeof st.unit === "string" && st.unit.length > 0 &&
    st.probability === 1.0;
}
function gate09TerminalRule(
  start: Gate09NativeHealthCheck,
  bySubject: Map<string, Gate09NativeHealthCheck>,
): Gate09NativeHealthCheck | null {
  // Cover cites earlier answer question/unit (evidence.rs:350-372);
  // Superseded.by names successor subject (wire_health.rs:110-119, evidence.rs:374-387).
  // Cycle-safe via visited sets, no cap number.
  const visited = new Set<string>();
  const seenQU = new Set<string>();
  let current: Gate09NativeHealthCheck | undefined = start;
  while (current) {
    if (visited.has(current.subject)) return null;
    visited.add(current.subject);
    const st = current.state;
    if (st.state === "answered") {
      if (st.answer !== "valid_burst") return null;
      if (typeof st.question !== "string" || st.question.length === 0) return null;
      if (typeof st.unit !== "string" || st.unit.length === 0) return null;
      if (gate09IsRuleBy(st.by)) {
        if (st.probability !== 1.0) return null;
        return current;
      }
      if (gate09IsCoverBy(st.by)) {
        if (st.probability !== 1.0) return null;
        const key = `${st.question}\0${st.unit}`;
        if (seenQU.has(key)) return null;
        seenQU.add(key);
        let found: Gate09NativeHealthCheck | undefined;
        for (const c of bySubject.values()) {
          const cs = c.state;
          if (cs.state === "answered" &&
            cs.answer === "valid_burst" &&
            cs.question === st.question &&
            cs.unit === st.unit &&
            gate09IsRuleBy(cs.by) &&
            cs.probability === 1.0) {
            found = c;
            break;
          }
        }
        if (!found) return null;
        current = found;
        continue;
      }
      return null;
    }
    if (st.state === "superseded") {
      const next = bySubject.get(st.by);
      if (!next) return null;
      current = next;
      continue;
    }
    return null;
  }
  return null;
}
suite.test(test, "GATE-09", "No fixed burst refusal should work", async () => {
  const engine = await EngineFixture.start({ id: "GATE-09", profile });
  let primaryFailed = false;
  let primary: unknown;
  try {
    const catalog = await loadFixtures();
    const scenarios = await catalog.readJson<{
      scenarios: Record<string, {
        owner_threshold_rows: FacadeInput<"vault.wire_health.thresholds.set">;
        writes: {
          count: number;
          concurrency: number;
          distinct_subjects: boolean;
          predicate: string;
          source: string;
          value_prefix: string;
        };
      }>;
    }>("gate-authority-consent-scenarios");
    const g09 = scenarios.scenarios["GATE-09"];
    if (!g09) throw new Error("Missing GATE-09 fixture scenario");
    const COUNT = g09.writes.count;
    await engine.requireHttpDoor("/v1/core/facade/vault.wire_health.thresholds.get", "POST");
    await engine.requireHttpDoor("/v1/core/facade/vault.wire_health.thresholds.set", "POST");
    const ownerHex = engine.pairedActor.principalRef;
    const occurred = 1769947200; // Public setup input, existing explicit time from memory.test.ts setup.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const scope = await ownerBaseClaimScope(engine.client, ownerHex);
    const persons: { idHex: string; entityRef: string; value: string }[] = [];
    for (let i = 0; i < COUNT; i++) {
      const name = `Courtyard Burst Person ${i}`;
      const witness = await engine.client.call("vault.witness", {
        conversation_ref: conversation.id,
        occurred_at: occurred,
        messages: [{
          author: "user", message_type: "text",
          content: `This distinct person is ${name}.`,
          is_visible: true, order: 0,
        }],
      } satisfies FacadeInput<"vault.witness">);
      const turn = await engine.client.call("vault.get", {
        entity_ref: witness.turn_short_id,
      } satisfies FacadeInput<"vault.get">);
      if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
        throw new Error("witnessed TURN missing");
      }
      const created = await engine.client.call("vault.people.create", {
        identity: { name },
        identity_evidence_refs: [turn.value.id_hex],
        occurred_at: occurred,
      } satisfies FacadeInput<"vault.people.create">);
      expect(created.person.id_hex).not.toBe(ownerHex);
      const got = await engine.client.call("vault.get", {
        entity_ref: created.person.entity_ref,
      } satisfies FacadeInput<"vault.get">);
      expect(got.value?.kind).toBe("PERSON");
      persons.push({
        idHex: created.person.id_hex,
        entityRef: created.person.entity_ref,
        value: `${g09.writes.value_prefix} ${i}`,
      });
    }
    expect(new Set(persons.map((p) => p.idHex)).size).toBe(COUNT);
    await engine.artifacts.json("gate09-persons.json", persons);
    const before = await engine.client.call("vault.wire_health.thresholds.get", {
    } satisfies FacadeInput<"vault.wire_health.thresholds.get">);
    const baseline = (await engine.client.request<Gate09NativeHealthList>(
      "GET", "/v1/owner/wire-health",
    )).body;
    const baselineSubjects = new Set(baseline.checks.map((c) => c.subject));
    await engine.artifacts.json("gate09-health-baseline.json", baseline);
    const receipt = await engine.client.call("vault.wire_health.thresholds.set", {
      window_secs: g09.owner_threshold_rows.window_secs,
      per_verb: g09.owner_threshold_rows.per_verb,
      per_actor: g09.owner_threshold_rows.per_actor,
    } satisfies FacadeInput<"vault.wire_health.thresholds.set">);
    expect(receipt.thresholds).toEqual(g09.owner_threshold_rows);
    const reread = await engine.client.call("vault.wire_health.thresholds.get", {
    } satisfies FacadeInput<"vault.wire_health.thresholds.get">);
    expect(reread).toEqual(g09.owner_threshold_rows);
    await engine.artifacts.json("gate09-thresholds.json", { before, receipt, reread });
    type UpsertInput = FacadeInput<"vault.claims.upsert">;
    type UpsertResult = FacadeResult<"vault.claims.upsert">;
    const inputs: UpsertInput[] = persons.map((p) => ({
      predicate: g09.writes.predicate,
      subject_ref: p.idHex,
      value: p.value,
      confidence: 1, // Ordinary user_stated, matches memory.test.ts canonical translation.
      source: g09.writes.source,
      scope,
      occurred_at: occurred,
    } satisfies UpsertInput));
    const settled: PromiseSettledResult<UpsertResult>[] = await Promise.allSettled(
      inputs.map((input) => engine.client.call("vault.claims.upsert", input)),
    );
    expect(settled).toHaveLength(COUNT);
    const fulfilled: { index: number; receipt: UpsertResult }[] = [];
    const rejected: {
      index: number;
      httpStatus: number | null;
      code: string;
      message: string;
      body: unknown;
    }[] = [];
    settled.forEach((row, index) => {
      if (row.status === "fulfilled") {
        fulfilled.push({ index, receipt: row.value });
      } else {
        const reason = row.reason;
        if (reason instanceof PublicHttpError) {
          const code = reason.error?.code ?? `HTTP_${reason.reply.status}`;
          const message = reason.error?.message ?? reason.message;
          rejected.push({
            index, httpStatus: reason.reply.status, code, message, body: reason.reply.body,
          });
        } else {
          rejected.push({
            index, httpStatus: null, code: "UNKNOWN",
            message: reason instanceof Error ? reason.message : String(reason), body: null,
          });
        }
      }
    });
    // Keep all outcomes before a later audit read can fail. A rejected input
    // cannot be matched to PendingWrite by an index or an arbitrary error string.
    await engine.artifacts.json("gate09-burst-outcomes.json", { inputs, fulfilled, rejected });
    expect(fulfilled.length + rejected.length).toBe(COUNT);
    if (rejected.length > 0) {
      throw new Error(
        `GATE-09 burst has ${rejected.length} rejections; owner ordinary writes expect all ${COUNT} accepted; see gate09-burst-outcomes.json`,
      );
    }
    for (const row of fulfilled) {
      expect(row.receipt.receipt_ref.length).toBeGreaterThan(0);
      expect(row.receipt.claim_short_id.length).toBeGreaterThan(0);
    }
    const pending = await engine.client.call("vault.writes.pending", {
      limit: 1000,
    } satisfies FacadeInput<"vault.writes.pending">);
    const receiptsPage = await engine.client.call("vault.receipts", {
      limit: 1000,
    } satisfies FacadeInput<"vault.receipts">);
    await engine.artifacts.json("gate09-burst-audit.json", { pending, receipts: receiptsPage.receipts });
    let lastHealth = baseline;
    let answered: Gate09NativeHealthList;
    try {
      answered = await awaitPublic(
        async () => {
          lastHealth = (await engine.client.request<Gate09NativeHealthList>(
            "GET", "/v1/owner/wire-health",
          )).body;
          return lastHealth;
        },
        (list) => {
          const bySubject = new Map<string, Gate09NativeHealthCheck>();
          for (const row of list.checks) bySubject.set(row.subject, row);
          const burst = list.checks.filter((c) => gate09IsBurst(c, baselineSubjects, ownerHex, GATE09_UPSERT_VERB));
          if (burst.length < 1) return false;
          let hasDirect = false;
          for (const c of burst) {
            if (gate09IsDirectRuleValidBurst(c)) hasDirect = true;
            const terminal = gate09TerminalRule(c, bySubject);
            if (!terminal) return false;
            if (!gate09IsBurst(terminal, baselineSubjects, ownerHex, GATE09_UPSERT_VERB)) return false;
          }
          return hasDirect;
        },
        { label: "burst wire checks answered valid_burst at rule rung", timeoutMs: LIMITS.flowMs },
      );
    } catch (error) {
      await engine.artifacts.json("gate09-health-observed.json", lastHealth).catch(() => {});
      throw error;
    }
    await engine.artifacts.json("gate09-health-answered.json", answered);
    const burstChecks = answered.checks.filter((c) => gate09IsBurst(c, baselineSubjects, ownerHex, GATE09_UPSERT_VERB));
    expect(burstChecks.length).toBeGreaterThanOrEqual(1);
    for (const check of burstChecks) {
      expect(check.crossing.per_verb).toBe(g09.owner_threshold_rows.per_verb);
      expect(check.crossing.per_actor).toBe(g09.owner_threshold_rows.per_actor);
      expect(check.crossing.verbs.some((v) => v.verb === GATE09_UPSERT_VERB && v.calls > g09.owner_threshold_rows.per_verb)).toBe(true);
      expect(check.crossing.actors.some((a) => a.actor === ownerHex && a.calls > g09.owner_threshold_rows.per_actor)).toBe(true);
      expect(check.state.state).not.toBe("asked");
    }
    const readbacks: { index: number; subject: string; expected: string; found: unknown }[] = [];
    for (let i = 0; i < persons.length; i++) {
      const p = persons[i]!;
      const list = await engine.client.call("vault.claims.list", {
        subject_ref: p.idHex, predicate: g09.writes.predicate, limit: 1000,
      } satisfies FacadeInput<"vault.claims.list">);
      expect(list.value).toHaveLength(1);
      expect(list.value[0]!.subject_ref).toBe(p.idHex);
      expect(list.value[0]!.predicate).toBe(g09.writes.predicate);
      expect(list.value[0]!.value).toBe(p.value);
      readbacks.push({ index: i, subject: p.idHex, expected: p.value, found: list.value[0]!.value });
    }
    await engine.artifacts.json("gate09-exact-readbacks.json", readbacks);
  } catch (error) {
    primaryFailed = true;
    primary = error;
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
