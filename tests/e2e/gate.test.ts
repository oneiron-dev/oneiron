import { afterAll, test } from "bun:test";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Authority and consent, in plan order. All nine COMPLETE flows are blocked.
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
// Existing public GET /v1/owner/wire-health -> {checks: HealthCheck[]} and
// POST /wire-health/outcome {unit, outcome: bot|valid_burst} -> {fact} are real.
// Missing: owner threshold-row read/edit for this self-hosted fixture. The
// WireTelemetry.set_thresholds Rust method and managed-host messages are NOT a
// public owner call. Never write a private counter/key or patch a config file.
// Waiting shape: per-actor/per-verb detection rows + window -> policy receipt;
// crossing -> typed health question -> ladder verdict or durable held ask.
// Send exactly 40 distinct authorized ordinary writes with Promise.all, retaining
// every intent's receipt/error; never retry a refused write. Read all 40 values
// (no top-k recall as a completeness oracle). Every intent is accepted or has a
// documented durable queue entry, never dropped or refused for a fixed rate.
// Await PUBLIC health observation (not sleep/private tick); a known granted actor
// is valid_burst at the rule rung. Check question, verdict and receipt association.
// The fixture's threshold 5 and window 1 s are explicit owner test policy, not
// engine defaults. Do not assert universal Idempotency-Key support for upserts:
// canon's 24-hour keyed consume-once contract is the MESSAGE-APPEND surface.
type Gate09ThresholdRows = { window_secs: number; per_verb: number; per_actor: number };
type Gate09HealthState =
  | { state: "held" }
  | { state: "asked"; question: Ref; unit: Ref }
  | { state: "answered"; answer: "bot" | "valid_burst"; question: Ref; unit: Ref };
suite.todo(test, "GATE-09", "waits on typed owner wire-health detection threshold read/edit for an authorized 40-write burst");
