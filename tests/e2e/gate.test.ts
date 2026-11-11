import { afterAll, expect, test } from "bun:test";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { McpRpcError, PublicHttpError } from "./support/clients.ts";
import { ScriptedProviders } from "./support/providers.ts";
import { inflateRawSync } from "node:zlib";
import type { PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { BlockedDoor, defineFile, LIMITS, redactor, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Authority and consent, in plan order. GATE-01, 03, 04, 06, 07 and 08 are written as the subset their
 * doors drive today, each named for exactly that subset (E2E-PARTIAL); each case's note lists what stays
 * unproved and the missing door. GATE-02 and GATE-05 are pending doors (Engine CORE-FOUR-SKIPS = A): each
 * reports SKIPPED with its missing door and FIX row until 2026-12-01, then FAIL. GATE-09 exercises the
 * authorized write burst.
 * Do not turn a partial claim write or a schema lookup into passing coverage.
 *
 * Authored inputs and independent oracles: fixtures/gate/scenarios.json,
 * pinned by fixtures/gate/manifest.json. The runner verifies that fragment even
 * for TODO-only files. No fixture is a stored vault or a privileged log entry.
 *
 * Binding read: main 5ecd5af5bea2c70e25760f0583f276790f49fba4.
 * Inspected scripts/sdk/verbs/, packages/oneiron-client/src/{facade,
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

// Shared setup for the written cases. Every call is a typed public door; the agents are real
// principals minted by the stopped-vault `token agent` CLI, as boot.test.ts and hooks.test.ts do.
const GATE_T = 1769947200; // Public setup input (memory.test.ts), never an engine clock override.
type AgentTier = "read-only" | "propose-only" | "full-access";
async function enrolAgents(engine: EngineFixture, specs: readonly { name: string; tier: AgentTier }[]): Promise<PairedActor[]> {
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const principals: string[] = [];
  for (const spec of specs) {
    const minted = await engine.cli.run([
      "token", "agent", "--name", spec.name, "--tier", spec.tier,
      "--config", resolve(engine.root, "oneiron.toml"),
      "--out", resolve(engine.root, `${spec.name}.credential`),
    ], undefined, undefined, true);
    expect(minted.exitCode).toBe(0);
    const principal = JSON.parse(minted.stdout) as { principal_ref: string; actor_class: string };
    expect(principal.actor_class).toBe("agent");
    expect(principal.principal_ref).toMatch(/^[0-9a-f]{32}$/);
    principals.push(principal.principal_ref);
  }
  await engine.restart();
  const actors: PairedActor[] = [];
  for (const [index, spec] of specs.entries()) {
    const scope = spec.tier === "read-only" ? ["core:read"]
      : spec.tier === "propose-only" ? ["core:read", "core:propose"]
      : ["core:read", "core:propose", "core:write"];
    actors.push(await engine.pairActor({ principalRef: principals[index]!, actorClass: "agent", scope }));
  }
  return actors;
}
/** A refused public call: its HTTP status and stable error code, never just "it threw". */
async function refused(work: Promise<unknown>, status: number, code: string): Promise<PublicHttpError> {
  try { await work } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(status);
    expect(error.error?.code).toBe(code);
    return error;
  }
  throw new Error(`Expected HTTP ${status} ${code}, got success`);
}
/** One readable TURN to cite as a claim's evidence. */
async function evidenceTurn(engine: EngineFixture, content: string): Promise<string> {
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: GATE_T, occurred_end: GATE_T, learned_at: GATE_T,
  } satisfies FacadeInput<"vault.conversations.create">);
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: GATE_T,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  } satisfies FacadeInput<"vault.witness">);
  return witnessed.turn_id;
}
type PolicyManifest = FacadeInput<"vault.gate.policy.put">["manifest"];
type ActorCeilingRow = PolicyManifest["actor_ceilings"][number];
function policyManifest(pack_id: string, pack_version: string, actor_ceilings: ActorCeilingRow[]): PolicyManifest {
  return { schema_version: "1.2", pack_id, pack_version, min_engine_version: "0.0.0",
    defaults: {}, rules: [], actor_ceilings };
}
type GateReceipt = FacadeResult<"vault.receipts">["receipts"][number];
async function gateReceipt(engine: EngineFixture, receiptRef: string): Promise<GateReceipt> {
  const page = await engine.client.call("vault.receipts", { limit: 1000 });
  const row = page.receipts.find(item => item.receipt_ref === receiptRef);
  if (!row) throw new Error(`Gate receipt ${receiptRef} is not in the owner's ledger`);
  return row;
}

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
// Written subset (E2E-PARTIAL): each axis decides an external write on its own. An owner
// actor-ceiling row holds one agent's ordinary write while an identical write from another agent
// lands; a tool_output source holds a write the same agent's user_stated twin lands; and a
// critical predicate lands an auto write only with a critical confirmation attached, while the
// owner's own critical write carries its own. Unproved here: a Generated candidate requesting
// Auto (no public door asks Auto for `generated`) and the batch/MCP carriers.
suite.test(test, "GATE-01", "Actor ceiling, source and criticality each decide a write", async () => {
  const engine = await EngineFixture.start({ id: "GATE-01", profile });
  const owner = engine.pairedActor.principalRef;
  const scope = await ownerBaseClaimScope(engine.client, owner);
  const evidence = await evidenceTurn(engine, "Gate three-axis evidence: the owner states these preferences.");
  const [free, held] = await enrolAgents(engine, [
    { name: "gate01-free", tier: "full-access" }, { name: "gate01-held", tier: "full-access" },
  ]);
  const before = await engine.client.call("vault.gate.policy.get", {});
  const put = await engine.client.call("vault.gate.policy.put", { manifest: policyManifest("e2e-gate01-axes", "1", [
    { actor_class: "agent", actor_ref: free!.principalRef, ceiling: "auto" },
    { actor_class: "agent", actor_ref: held!.principalRef, ceiling: "proposed" },
  ]) });
  expect(put.approval).toBe("auto");
  expect(put.manifest.trusted).toBe(true);
  expect(put.read_frontier_hash).not.toBe(before.read_frontier_hash);
  const write = (actor: PairedActor, predicate: string, source: "user_stated" | "tool_output", value: string) =>
    actor.client.call("vault.claims.upsert", {
      predicate, subject_ref: owner, value, confidence: 1, source, scope,
      evidence_turn_refs: [evidence], occurred_at: GATE_T,
    } satisfies FacadeInput<"vault.claims.upsert">);
  const writes = {
    free: await write(free!, "profile.gate01.actor", "user_stated", "free agent ordinary"),
    held: await write(held!, "profile.gate01.actor_held", "user_stated", "held agent ordinary"),
    toolOutput: await write(free!, "profile.gate01.source", "tool_output", "free agent tool output"),
    critical: await write(free!, "health.gate01.allergy", "user_stated", "free agent critical"),
    ownerCritical: await write(engine.pairedActor, "health.gate01.owner_allergy", "user_stated", "owner critical"),
  };
  await engine.artifacts.json("gate01-writes.json", writes);
  const pending = await engine.client.call("vault.writes.pending", { limit: 1000 });
  await engine.artifacts.json("gate01-pending.json", pending);
  const ledger = (await engine.client.call("vault.receipts", { limit: 1000 })).receipts;
  await engine.artifacts.json("gate01-receipts.json", ledger);
  const receipt = (ref: string): GateReceipt => {
    const row = ledger.find(item => item.receipt_ref === ref);
    if (!row) throw new Error(`write receipt ${ref} missing from the ledger`);
    return row;
  };
  // Actor axis: the same ordinary user_stated write lands for one agent and waits for the other.
  expect(writes.free.approval).toBe("auto");
  expect(receipt(writes.free.receipt_ref)).toMatchObject({ outcome: "allow", actor_ref: free!.principalRef, actor_class: "agent" });
  expect(writes.held.approval).toBe("proposed");
  expect(receipt(writes.held.receipt_ref)).toMatchObject({ outcome: "pending", actor_ref: held!.principalRef, actor_class: "agent" });
  expect(receipt(writes.held.receipt_ref).reason_codes).toContain("gate.pending.actor_ceiling");
  // Source axis: the agent that lands user_stated is held for tool_output.
  expect(writes.toolOutput.approval).toBe("proposed");
  expect(receipt(writes.toolOutput.receipt_ref)).toMatchObject({ outcome: "pending", actor_ref: free!.principalRef });
  expect(receipt(writes.toolOutput.receipt_ref).reason_codes).toEqual(["gate.pending.source_trust"]);
  // Criticality axis: a critical predicate lands only with a confirmation attached; the owner's carries its own.
  // The critical markers are receipt reasons beside the allow code, read through the gate explanation.
  const explained = async (receipt: string) => (await engine.client.call("vault.explain.gate", { receipt }))?.receipt_reasons;
  expect(writes.critical.approval).toBe("auto");
  expect(await explained(writes.critical.receipt_ref)).toContain("gate.allow.critical_confirm_attached");
  expect(writes.ownerCritical.approval).toBe("auto");
  expect(await explained(writes.ownerCritical.receipt_ref)).toContain("gate.allow.critical_owner_authored");
  // Pending holds the two proposed writes and the agent's Auto critical write awaiting its confirmation;
  // neither the free write nor the owner's own critical write waits.
  const heldDecisions = new Set(pending.map(row => `gate:${row.decision_ref.replace(/^gate:/, "")}`));
  expect(heldDecisions.has(writes.held.receipt_ref)).toBe(true);
  expect(heldDecisions.has(writes.toolOutput.receipt_ref)).toBe(true);
  expect(heldDecisions.has(writes.critical.receipt_ref)).toBe(true);
  expect(heldDecisions.has(writes.free.receipt_ref)).toBe(false);
  expect(heldDecisions.has(writes.ownerCritical.receipt_ref)).toBe(false);
  // Stored provenance is the writer's, as the credential stamped it.
  const stored = await engine.client.call("vault.claims.list", { subject_ref: owner, limit: 1000 });
  const claim = (predicate: string) => stored.value.find(row => row.predicate === predicate);
  expect(claim("profile.gate01.actor")).toMatchObject({ approval: "auto", source: "user_stated" });
  expect(claim("profile.gate01.actor_held")).toMatchObject({ approval: "proposed", source: "user_stated" });
  expect(claim("profile.gate01.source")).toMatchObject({ approval: "proposed", source: "tool_output" });
  // An agent cannot widen its own ceiling: policy edits stay with the owner.
  await refused(held!.client.call("vault.gate.policy.put", { manifest: policyManifest("e2e-gate01-self-widen", "1", [
    { actor_class: "agent", actor_ref: held!.principalRef, ceiling: "auto" },
  ]) }), 403, "FORBIDDEN");
});

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
// Pending door (Engine CORE-FOUR-SKIPS = A): SKIPPED with its door and FIX row until the deadline, then FAIL.
suite.pendingDoor(test, "GATE-02",
  "waits on a public door that runs a Dreamer consolidation whose candidate write the enforced checker judges; vault.gate.checker.set needs a vault model manifest, and a plain claim upsert never consults the checker. Veto-only content checker should work",
  { fix: "FIX 22527", deadline: "2026-12-01" });

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
// GATE-03 written subset (E2E-PARTIAL): only the owner changes policy; an agent's proposal, in
// either direction, stays an untrusted proposal; a stale body hash is refused; and the owner's
// edit survives a restart. Unproved here: the observed write decisions after two contributions
// compose by meet (GATE-01 proves one contribution's actor rows decide writes).
suite.test(test, "GATE-03", "Only the owner changes policy, proposals stay inert, and owner policy survives a restart", async () => {
  const engine = await EngineFixture.start({ id: "GATE-03", profile });
  const [agent] = await enrolAgents(engine, [{ name: "gate03-agent", tier: "full-access" }]);
  const before = await engine.client.call("vault.gate.policy.get", {});
  const shipped = before.manifests.find(row => row.manifest_ref === before.default_manifest_ref);
  expect(shipped).toBeDefined();
  expect(shipped!).toMatchObject({ trusted: true, quarantined: false });
  expect(shipped!.manifest.pack_id).toBe("oneiron-default-policy");
  const restriction = policyManifest("e2e-gate03-restriction", "1", [
    { actor_class: "agent", actor_ref: agent!.principalRef, ceiling: "proposed" },
  ]);
  const put = await engine.client.call("vault.gate.policy.put", { manifest: restriction });
  expect(put).toMatchObject({ approval: "auto", manifest: { trusted: true, quarantined: false } });
  const one = await engine.client.call("vault.gate.policy.get", { manifest_ref: put.manifest.manifest_ref });
  expect(one.manifests).toHaveLength(1);
  expect(one.manifests[0]!.body_hash).toBe(put.manifest.body_hash);
  expect(one.manifests[0]!.manifest.actor_ceilings).toEqual(restriction.actor_ceilings);
  // An agent can neither write nor read policy; a signature marker is not authority.
  await refused(agent!.client.call("vault.gate.policy.put", { manifest: {
    ...policyManifest("e2e-gate03-agent-put", "1", [{ actor_class: "agent", actor_ref: agent!.principalRef, ceiling: "auto" }]),
    signatures: [{ alg: "ed25519", sig: "e2e-signature-marker" }],
  } }), 403, "FORBIDDEN");
  await refused(agent!.client.call("vault.gate.policy.get", {}), 403, "FORBIDDEN");
  // An agent may propose, wider or tighter: each stays an untrusted proposal.
  const wider = await agent!.client.call("vault.gate.policy.propose", { manifest: policyManifest("e2e-gate03-wider", "1", [
    { actor_class: "agent", actor_ref: agent!.principalRef, ceiling: "auto" },
  ]) });
  const tighter = await agent!.client.call("vault.gate.policy.propose", { manifest: policyManifest("e2e-gate03-tighter", "1", [
    { actor_class: "human", ceiling: "proposed" },
  ]) });
  for (const proposal of [wider, tighter]) {
    expect(proposal.approval).toBe("proposed");
    expect(proposal.manifest.trusted).toBe(false);
  }
  expect(wider.manifest.manifest_ref).not.toBe(tighter.manifest.manifest_ref);
  // The owner edits with the current body hash only.
  const edited = { ...restriction, pack_version: "2" };
  await refused(engine.client.call("vault.gate.policy.put", {
    manifest_ref: put.manifest.manifest_ref, expected_body_hash: "0".repeat(64), manifest: edited,
  }), 400, "BAD_REQUEST");
  const edit = await engine.client.call("vault.gate.policy.put", {
    manifest_ref: put.manifest.manifest_ref, expected_body_hash: put.manifest.body_hash, manifest: edited,
  });
  expect(edit.manifest.manifest_ref).toBe(put.manifest.manifest_ref);
  expect(edit.manifest.body_hash).not.toBe(put.manifest.body_hash);
  await engine.restart();
  const after = await engine.client.call("vault.gate.policy.get", {});
  const byRef = (ref: string) => after.manifests.find(row => row.manifest_ref === ref);
  expect(after.default_manifest_ref).toBe(before.default_manifest_ref);
  expect(byRef(before.default_manifest_ref)!.body_hash).toBe(shipped!.body_hash);
  expect(byRef(put.manifest.manifest_ref)).toMatchObject({ body_hash: edit.manifest.body_hash, trusted: true,
    manifest: { pack_version: "2", actor_ceilings: restriction.actor_ceilings } });
  expect(byRef(wider.manifest.manifest_ref)?.trusted).toBe(false);
  expect(byRef(tighter.manifest.manifest_ref)?.trusted).toBe(false);
  expect(after.read_frontier_hash).toBe(edit.read_frontier_hash);
  for (const ref of [put.receipt_ref, edit.receipt_ref]) {
    const row = await gateReceipt(engine, ref);
    expect(row).toMatchObject({ outcome: "allow", actor_ref: engine.pairedActor.principalRef });
    expect(row.reason_codes).toContain("gate.allow.owner_policy_manifest");
  }
  for (const proposal of [wider, tighter])
    expect((await gateReceipt(engine, proposal.receipt_ref)).actor_ref).toBe(agent!.principalRef);
});

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
// GATE-04 written subset (E2E-PARTIAL): only the owner grants standing consent; a wider bound is a
// new grant, never a change to the old one; revoke ends a grant once, and a repeat revoke reports
// the first. Unproved here, with the missing door: "a standing grant auto-covers reuse inside its
// bound and wider use asks again" needs a public effect door that composes an action-consent
// effect and returns its ask and digest; approve_once has no engine-emitted digest to approve.
suite.test(test, "GATE-04", "Only the owner grants standing consent, a wider bound is a new grant, and revoke ends it once", async () => {
  const engine = await EngineFixture.start({ id: "GATE-04", profile });
  const owner = engine.pairedActor.principalRef;
  const [agent] = await enrolAgents(engine, [{ name: "gate04-agent", tier: "full-access" }]);
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: GATE_T, occurred_end: GATE_T, learned_at: GATE_T,
  });
  const bound = { audience: [owner], class: "health", envelope: { selectors: [`conversation:${conversation.id}`] } };
  await refused(agent!.client.call("vault.consent.create_standing_grant", { bound }), 403, "FORBIDDEN");
  const created = await engine.client.call("vault.consent.create_standing_grant", { bound });
  expect(created).toMatchObject({ outcome: "approved", reason_code: "gate.consent.standing_created" });
  expect(created.grant_ref).toMatch(/^[0-9a-f]{64}$/);
  const wider = await engine.client.call("vault.consent.create_standing_grant", {
    bound: { ...bound, envelope: { selectors: [`conversation:${conversation.id}`, `person:${owner}`] } },
  });
  expect(wider.outcome).toBe("approved");
  expect(wider.grant_ref).not.toBe(created.grant_ref);
  const registry = await engine.client.call("vault.consent.registry", { limit: 100 });
  const row = registry.rows.find(item => item.grant_ref === created.grant_ref);
  expect(row).toMatchObject({ domain: "disclosure", status: "active", class: "health",
    revoke_action: { command: "vault.consent.revoke", grant_ref: created.grant_ref } });
  expect(row!.selectors).toEqual(expect.arrayContaining([`conversation:${conversation.id}`]));
  expect(registry.rows.find(item => item.grant_ref === wider.grant_ref)?.status).toBe("active");
  await refused(agent!.client.call("vault.consent.revoke", { grant: created.grant_ref! }), 403, "FORBIDDEN");
  const revoked = await engine.client.call("vault.consent.revoke", { grant: created.grant_ref! });
  expect(revoked).toMatchObject({ outcome: "revoked", reason_code: "gate.consent.revoked" });
  expect(revoked.already_revoked ?? false).toBe(false);
  const again = await engine.client.call("vault.consent.revoke", { grant: created.grant_ref! });
  expect(again.already_revoked).toBe(true);
  expect(again.decision_ref).toBe(revoked.decision_ref);
  const afterRevoke = await engine.client.call("vault.consent.registry", { limit: 100, include_revoked: true });
  expect(afterRevoke.rows.find(item => item.grant_ref === created.grant_ref)?.status).toBe("revoked");
  expect(afterRevoke.rows.find(item => item.grant_ref === wider.grant_ref)?.status).toBe("active");
  const active = await engine.client.call("vault.consent.registry", { limit: 100 });
  expect(active.rows.some(item => item.grant_ref === created.grant_ref)).toBe(false);
  for (const act of [created, revoked])
    expect((await gateReceipt(engine, `gate:${act.decision_ref}`)).actor_ref).toBe(owner);
  await refused(engine.client.call("vault.consent.approve_once", { effect_digest: "not-a-digest" }), 400, "BAD_REQUEST");
});

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
// Pending door (Engine CORE-FOUR-SKIPS = A).
suite.pendingDoor(test, "GATE-05",
  "waits on typed attenuating agent delegation, parent-grant revoke and delegated read/action grant setup. Delegation attenuation and subtree revoke should work",
  { fix: "FIX 22528", deadline: "2026-12-01" });

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
// GATE-06 written subset (E2E-PARTIAL): only the owner creates a catastrophe-floor bypass, and only
// from the warning the engine computed, unchanged; the bypass is bound to one thread and readable
// as active state; revoke ends it and its bypassed-effect record stays readable. Unproved here,
// with the missing door: "auto-approves only its scope" needs a public door that performs a
// composed catastrophe operation inside and outside the bound and returns its ask or receipt;
// the project variant needs a public door that mints a non-root PROJECT without the decider.
suite.test(test, "GATE-06", "Only the owner creates a thread-scoped bypass from an unchanged warning, and revoke ends it", async () => {
  const engine = await EngineFixture.start({ id: "GATE-06", profile });
  const owner = engine.pairedActor.principalRef;
  const [agent] = await enrolAgents(engine, [{ name: "gate06-agent", tier: "full-access" }]);
  const thread = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: GATE_T, occurred_end: GATE_T, learned_at: GATE_T,
  });
  const bound = { actor: agent!.principalRef, actor_class: "agent", classes: ["SecurityControlDisable" as const],
    scope: { thread: thread.id }, envelope: { selectors: [`thread:${thread.id}`], target: thread.id, receipt_required: true } };
  await refused(agent!.client.call("vault.consent.bypass_grant_warning", { bound }), 403, "FORBIDDEN");
  const warning = await engine.client.call("vault.consent.bypass_grant_warning", { bound });
  expect(warning.owner).toBe(owner);
  expect(warning.bound).toMatchObject({ actor: agent!.principalRef, classes: ["SecurityControlDisable"], scope: { thread: thread.id } });
  expect(warning.bound_digests).toHaveLength(1);
  expect(warning.floor_version).toBeGreaterThan(0);
  await refused(agent!.client.call("vault.consent.create_bypass_grant", { warning }), 403, "FORBIDDEN");
  await refused(engine.client.call("vault.consent.create_bypass_grant", {
    warning: { ...warning, floor_version: warning.floor_version + 1 },
  }), 400, "BAD_REQUEST");
  const receipts = await engine.client.call("vault.consent.create_bypass_grant", { warning });
  expect(receipts).toHaveLength(1);
  const grant = receipts[0]!;
  expect(grant).toMatchObject({ outcome: "approved", reason_code: "gate.consent.bypass_created" });
  expect(grant.grant_ref).toMatch(/^[0-9a-f]{64}$/);
  expect(grant.grant_ref).not.toBe(warning.bound_digests[0]);
  const active = await engine.client.call("vault.consent.active_bypass_grants", {});
  const state = active.find(row => row.grant === grant.grant_ref);
  expect(state).toMatchObject({ active: true, floor_version: warning.floor_version,
    bound: { actor: agent!.principalRef, classes: ["SecurityControlDisable"], scope: { thread: thread.id },
      envelope: { selectors: [`thread:${thread.id}`], target: thread.id, receipt_required: true } } });
  await refused(agent!.client.call("vault.consent.active_bypass_grants", {}), 403, "FORBIDDEN");
  expect(await engine.client.call("vault.consent.bypassed_effect_receipts", { grant: grant.grant_ref! })).toEqual([]);
  await refused(agent!.client.call("vault.consent.revoke", { grant: grant.grant_ref! }), 403, "FORBIDDEN");
  expect(await engine.client.call("vault.consent.revoke", { grant: grant.grant_ref! })).toMatchObject({ outcome: "revoked" });
  expect((await engine.client.call("vault.consent.active_bypass_grants", {})).some(row => row.grant === grant.grant_ref)).toBe(false);
  expect(await engine.client.call("vault.consent.bypassed_effect_receipts", { grant: grant.grant_ref! })).toEqual([]);
  expect((await gateReceipt(engine, `gate:${grant.decision_ref}`)).actor_ref).toBe(owner);
});

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
// GATE-07 written subset (E2E-PARTIAL): the owner reviews an agent's proposed claims as one run,
// accepts them in one owner act, reads the same settlement back, then undoes one selected claim and
// then the remainder; compensations append and repeat without redoing. Unproved here, with the
// missing doors: the cross-kind bundle (edge, note fork, topology, one-way external effect) and
// dependent later work need public doors that produce those changes for a run.
suite.test(test, "GATE-07", "The owner accepts an agent's proposed claims as one run and undoes them selectively", async () => {
  const engine = await EngineFixture.start({ id: "GATE-07", profile });
  const owner = engine.pairedActor.principalRef;
  const scope = await ownerBaseClaimScope(engine.client, owner);
  const evidence = await evidenceTurn(engine, "Gate review evidence: two preferences to review.");
  // The HTTP facade's claim upsert needs core:write (a propose-only agent proposes through /v1/core/propose
  // or MCP), so the agent is full-access; its tool_output source still holds each claim as Proposed.
  const [agent] = await enrolAgents(engine, [{ name: "gate07-proposer", tier: "full-access" }]);
  const propose = (predicate: string, value: string) => agent!.client.call("vault.claims.upsert", {
    predicate, subject_ref: owner, value, confidence: 1, source: "tool_output", scope,
    evidence_turn_refs: [evidence], occurred_at: GATE_T,
  } satisfies FacadeInput<"vault.claims.upsert">);
  const first = await propose("profile.gate07.first", "first reviewed preference");
  const second = await propose("profile.gate07.second", "second reviewed preference");
  expect([first.approval, second.approval]).toEqual(["proposed", "proposed"]);
  const listed = await engine.client.call("vault.claims.list", { subject_ref: owner, limit: 1000 });
  const ref = (predicate: string) => {
    const row = listed.value.find(item => item.predicate === predicate);
    if (!row) throw new Error(`proposed claim ${predicate} missing`);
    return row.claim_ref;
  };
  const x = ref("profile.gate07.first"), y = ref("profile.gate07.second");
  const review: FacadeInput<"vault.runs.review"> = { run_id: "gate07-claims",
    changes: [{ kind: "claim", claim_ref: x }, { kind: "claim", claim_ref: y }] };
  const reviewed = await engine.client.call("vault.runs.review", review);
  expect(reviewed.review_id).toMatch(/^[0-9a-f]{64}$/);
  expect(reviewed.changes.map(change => change.verdict)).toEqual(["waiting", "waiting"]);
  expect(reviewed.explainer.text.length).toBeGreaterThan(0);
  await refused(agent!.client.call("vault.runs.review", review), 403, "FORBIDDEN");
  await refused(agent!.client.call("vault.runs.settle", { review, review_id: reviewed.review_id, decision: "approve" }), 403, "FORBIDDEN");
  const settled = await engine.client.call("vault.runs.settle", { review, review_id: reviewed.review_id, decision: "approve" });
  expect(settled).toMatchObject({ kind: "ProposalOutcome", verdict: "landed", reason: "owner_approved" });
  expect(settled.changes.map(change => change.verdict)).toEqual(["landed", "landed"]);
  expect(settled.answered_by).toEqual({ word_ref: settled.receipt });
  expect(await engine.client.call("vault.runs.settlement", { run_id: settled.revert_handle })).toEqual(settled);
  // A second settle of the same run is refused: one owner act settles it once.
  await refused(engine.client.call("vault.runs.settle", { review, review_id: reviewed.review_id, decision: "approve" }),
    400, "BAD_REQUEST");
  const lifecycle = async () => {
    const rows = (await engine.client.call("vault.claims.list", { subject_ref: owner, limit: 1000 })).value;
    return (claim: string) => rows.find(item => item.claim_ref === claim)?.lifecycle;
  };
  const landed = await lifecycle();
  expect([landed(x), landed(y)]).toEqual(["active", "active"]);
  const selective = await engine.client.call("vault.revert_run", { run_id: settled.revert_handle, changes: [x] });
  expect(selective.compensated.map(row => row.change)).toEqual([x]);
  expect(selective.not_undone).toEqual([{ change: y, reason: "not_selected" }]);
  const afterOne = await lifecycle();
  expect([afterOne(x), afterOne(y)]).toEqual(["retracted", "active"]);
  const rest = await engine.client.call("vault.revert_run", { run_id: settled.revert_handle });
  const compensation = new Map(rest.compensated.map(row => [row.change, row.receipt]));
  expect(compensation.get(x)).toBe(selective.compensated[0]!.receipt);
  expect(compensation.get(y)).toBeDefined();
  expect(compensation.get(y)).not.toBe(compensation.get(x));
  const afterAll = await lifecycle();
  expect([afterAll(x), afterAll(y)]).toEqual(["retracted", "retracted"]);
  expect((await gateReceipt(engine, settled.receipt)).actor_ref).toBe(owner);
  // Each compensating write is the owner's authored decision, recorded as approved.
  for (const receipt of compensation.values()) expect((await gateReceipt(engine, receipt)).outcome).toBe("approved");
});

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
// GATE-08 written subset (E2E-PARTIAL): a critical write by a non-owner person lands with a
// confirmation the owner must answer on its exact engine-issued binding. The writer cannot answer
// it, a wrong nonce is stale, the owner's clear is receipted and ends the pending row, and the
// owner's decline retracts a second one. Unproved here, with the missing doors: the low-confidence
// Generated candidate (no public door asks Auto for `generated`) and the read floors
// (critical_over_budget and critical_count are context-pack outputs, a door this case does not name).
suite.test(test, "GATE-08", "Only the owner clears or declines a critical write, on its exact binding", async () => {
  const engine = await EngineFixture.start({ id: "GATE-08", profile });
  const owner = engine.pairedActor.principalRef;
  const scope = await ownerBaseClaimScope(engine.client, owner);
  const evidence = await evidenceTurn(engine, "Gate critical evidence: Courtyard Critical Writer states two health facts.");
  const person = await engine.client.call("vault.people.create", {
    identity: { name: "Courtyard Critical Writer" }, identity_evidence_refs: [evidence], occurred_at: GATE_T,
  });
  const writer = await engine.pairActor({ principalRef: person.person.id_hex, actorClass: "human",
    scope: ["core:read", "core:propose", "core:write"] });
  const critical = (predicate: string, value: string) => writer.client.call("vault.claims.upsert", {
    predicate, subject_ref: owner, value, confidence: 0.05, source: "user_stated", scope,
    evidence_turn_refs: [evidence], occurred_at: GATE_T,
  } satisfies FacadeInput<"vault.claims.upsert">);
  const cleared = await critical("health.gate08.allergy", "courtyard pollen allergy");
  expect(cleared.approval).toBe("auto");
  const first = await engine.client.call("vault.writes.critical_confirm.pending", { pending_operation: cleared.receipt_ref });
  if (!first) throw new Error("critical write has no pending confirmation");
  expect(first.pending_operation).toBe(cleared.receipt_ref);
  expect(first.nonce).toMatch(/^[0-9a-f]{32}$/);
  expect(first.read_frontier_hash).toMatch(/^[0-9a-f]{64}$/);
  const binding = { pending_operation: first.pending_operation, nonce: first.nonce, read_frontier_hash: first.read_frontier_hash };
  await refused(writer.client.call("vault.writes.critical_confirm.pending", { pending_operation: cleared.receipt_ref }), 403, "FORBIDDEN");
  await refused(writer.client.call("vault.writes.critical_confirm.clear", binding), 403, "FORBIDDEN");
  const otherNonce = (first.nonce[0] === "0" ? "1" : "0") + first.nonce.slice(1);
  await refused(engine.client.call("vault.writes.critical_confirm.clear", { ...binding, nonce: otherNonce }), 409, "INVALID_STATE");
  const clear = await engine.client.call("vault.writes.critical_confirm.clear", binding);
  expect(clear.resolution).toBe("Cleared");
  expect(clear.receipt).toMatchObject({ disposition: "clear", confirm_id: first.confirm_id, claim_ref: first.claim_ref,
    nonce: first.nonce, read_frontier_hash: first.read_frontier_hash, effect_digest: first.effect_digest });
  expect(clear.receipt.receipt_ref).toMatch(/^authority:[0-9a-f]{64}$/);
  expect(await engine.client.call("vault.writes.critical_confirm.receipt", { confirm_id: first.confirm_id })).toEqual(clear.receipt);
  expect(await engine.client.call("vault.writes.critical_confirm.pending", { pending_operation: cleared.receipt_ref })).toBeNull();
  await refused(engine.client.call("vault.writes.critical_confirm.clear", binding), 409, "INVALID_STATE");
  const declined = await critical("safety.gate08.limit", "no ladders above two metres");
  const second = await engine.client.call("vault.writes.critical_confirm.pending", { pending_operation: declined.receipt_ref });
  if (!second) throw new Error("second critical write has no pending confirmation");
  expect(second.confirm_id).not.toBe(first.confirm_id);
  const decline = await engine.client.call("vault.writes.critical_confirm.decline", {
    pending_operation: second.pending_operation, nonce: second.nonce, read_frontier_hash: second.read_frontier_hash });
  expect(decline.resolution).toBe("Retracted");
  expect(decline.receipt).toMatchObject({ disposition: "decline", confirm_id: second.confirm_id, claim_ref: second.claim_ref });
  expect(await engine.client.call("vault.writes.critical_confirm.receipt", { confirm_id: second.confirm_id })).toEqual(decline.receipt);
  const rows = (await engine.client.call("vault.claims.list", { subject_ref: owner, limit: 1000 })).value;
  const kept = rows.find(row => row.claim_ref === first.claim_ref);
  expect(kept?.lifecycle).toBe("active");
  expect(kept?.confidence).toBeCloseTo(0.05, 6);
  expect(rows.find(row => row.claim_ref === second.claim_ref)?.lifecycle).toBe("retracted");
});

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

// MUSE-GATE-01 — standing consent Grant lifecycle for one outbound action.
// Promises (draft promise register): P-GATE-002, P-GATE-003, P-GATE-004,
// P-GATE-010, all from DEC-0006 #model. Source lines are in the report.
// Doors used: vault.structural.put, EngineFixture.pairActor (setup only),
// ownerBaseClaimScope, vault.agents.verb_classes.get/configure (public
// verb-class vocabulary), can (typed effect preflight), raw POST
// /v1/core/facade/connector.outbound.schedule (to see the 202 ask envelope),
// connector.outbound.schedule, vault.consent.create_standing_grant,
// vault.consent.registry, vault.consent.revoke, vault.receipts,
// engine.restart().
// Proof order (F3): no Grant asks with a receipt; inside the Grant two
// distinct in-envelope schedules do not ask and the run is receipted; an
// audience outside the envelope asks again; the agent cannot mint or revoke
// the Grant itself with a receipt; owner registry revoke; the loser agent
// asks again at its next use. Not proved: P-GATE-021 guest grant
// (non-transitive unless a live reciprocal Connect pact is available),
// a disclosure read, approve-once settlement, MCP tools/call and actual
// external delivery. See MUSE-GATE-01.report.md for each gap and door.

function museGate01Error(body: unknown): { code: string; message: string } | null {
  if (typeof body !== "object" || body === null) return null;
  const record = body as Record<string, unknown>;
  const inner = record.error;
  const source = typeof inner === "object" && inner !== null
    ? inner as Record<string, unknown> : record;
  return typeof source.code === "string" && typeof source.message === "string"
    ? { code: source.code, message: source.message } : null;
}

suite.test(test, "MUSE-GATE-01", "A standing action Grant lets a bounded outbound schedule run without a fresh ask until the owner revokes it", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-GATE-01", profile });
  let stage = "setup actors and verb class";
  let lastCan: unknown;
  try {
    const occurred = 1769947200; // The same public setup-time value GATE-09 uses.
    const ownerRef = engine.pairedActor.principalRef;

    const museGate01ReceiptRefs = async (): Promise<Set<string>> => new Set(
      (await engine.client.call("vault.receipts", {
        limit: 1000,
      } satisfies FacadeInput<"vault.receipts">)).receipts.map((row) => row.receipt_ref),
    );
    const museGate01ExpectNewReceipt = async (
      before: Set<string>,
      actorRef: string,
      label: string,
    ): Promise<void> => {
      const page = await awaitPublic(
        () => engine.client.call("vault.receipts", {
          limit: 1000,
        } satisfies FacadeInput<"vault.receipts">),
        (value) => value.receipts.some((row) =>
          !before.has(row.receipt_ref) && row.actor_ref === actorRef),
        { label, timeoutMs: LIMITS.requestMs },
      );
      const row = page.receipts.find((candidate) =>
        !before.has(candidate.receipt_ref) && candidate.actor_ref === actorRef);
      if (!row) throw new Error("Expected a new governing receipt for the actor");
      expect(row.receipt_ref.length).toBeGreaterThan(0);
    };

    // Setup actors through public doors only. As in SECRETS-01, the PERSON
    // record creates no authority; pairActor supplies the agent credential.
    const museGate01Person = async (name: string) =>
      engine.client.call("vault.structural.put", {
        kind: "PERSON",
        body: { name },
        occurred_at: occurred,
      } satisfies FacadeInput<"vault.structural.put">);
    const agentRecord = await museGate01Person("Muse Gate01 Agent");
    const insideAudience = await museGate01Person("Muse Gate01 Inside Audience");
    const outsideAudience = await museGate01Person("Muse Gate01 Outside Audience");
    const otherAgentRecord = await museGate01Person("Muse Gate01 Other Agent");
    const otherAgent = await engine.pairActor({
      principalRef: otherAgentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex,
      actorClass: "agent",
      // The substrate slip is not the variable in this case: the agent may
      // read and write, while only the standing consent Grant below changes.
      scope: ["core:read", "core:write"],
    });
    expect(agent.principalRef).toBe(agentRecord.id_hex);
    const agentReadback = await engine.client.call("vault.get", {
      entity_ref: agentRecord.entity_ref,
    } satisfies FacadeInput<"vault.get">);
    expect(agentReadback.value?.id_hex).toBe(agentRecord.id_hex);
    for (const audience of [insideAudience, outsideAudience, otherAgentRecord]) {
      expect((await engine.client.call("vault.get", { entity_ref: audience.entity_ref })).value?.id_hex)
        .toBe(audience.id_hex);
    }

    const project = (await ownerBaseClaimScope(
      engine.client,
      ownerRef,
    )).scope_project_id;
    expect(project.length).toBeGreaterThan(0);
    // Diagnostic only, with no assertion: if the outbound channel string
    // below names no shipped connector, this public catalog read shows the
    // builder which channel a fresh vault actually offers.
    await engine.artifacts.json(
      "muse-gate01-connectors.json",
      await agent.client.call("connector.list", {
      } satisfies FacadeInput<"connector.list">),
    );

    // The Grant names a verb class, never a raw verb. Read that class
    // vocabulary from its public door. If no row admits the outbound verb,
    // the owner appends one row to the rows read and checks the reread.
    const classView = await engine.client.call("vault.agents.verb_classes.get", {
    } satisfies FacadeInput<"vault.agents.verb_classes.get">);
    let classRow = classView.classes.find((row) =>
      row.verbs.includes("connector.outbound.schedule"));
    if (!classRow) {
      const madeClass = `muse_gate01_outbound_${secretHex(4)}`;
      redactor.add(madeClass);
      const configured = await engine.client.call("vault.agents.verb_classes.configure", {
        expected_body_hash: classView.body_hash,
        classes: [
          ...classView.classes,
          { name: madeClass, verbs: ["connector.outbound.schedule"] },
        ],
      } satisfies FacadeInput<"vault.agents.verb_classes.configure">);
      classRow = configured.configuration.classes.find((row) => row.name === madeClass);
    }
    if (!classRow) throw new Error("No public verb class covers connector.outbound.schedule");
    const className = classRow.name;
    redactor.add(className);
    const classReread = await engine.client.call("vault.agents.verb_classes.get", {
    } satisfies FacadeInput<"vault.agents.verb_classes.get">);
    expect(classReread.classes.some((row) =>
      row.name === className && row.verbs.includes("connector.outbound.schedule"))).toBe(true);

    const museGate01Outbound = (
      targetRef: string,
    ): FacadeInput<"connector.outbound.schedule"> => {
      const idempotencyKey = `muse-gate01-${secretHex(8)}`;
      redactor.add(idempotencyKey);
      return {
        verb: "send",
        channel: "discord",
        target: targetRef,
        idempotency_key: idempotencyKey,
        trigger: "gap_queue",
        trigger_ref: agentRecord.entity_ref,
      } satisfies FacadeInput<"connector.outbound.schedule">;
    };
    const museGate01Can = async (
      input: FacadeInput<"connector.outbound.schedule">,
    ): Promise<string> => {
      const answer = await agent.client.call("can", {
        effect: { outbound_schedule: input },
      } satisfies FacadeInput<"can">);
      lastCan = answer;
      if (!("verdict" in answer)) {
        throw new Error("can effect preflight returned no effect verdict");
      }
      return answer.verdict;
    };
    const museGate01ExpectAsk = async (
      input: FacadeInput<"connector.outbound.schedule">,
    ): Promise<void> => {
      const scheduled = await agent.client.call("connector.outbound.schedule", input);
      expect(scheduled.gate_outcome).toBe("pending");
      if (!scheduled.gate_decision_ref) throw new Error("Held schedule has no Gate decision");
      const receipt = await gateReceipt(engine, `gate:${scheduled.gate_decision_ref.replace(/^gate:/, "")}`);
      expect(receipt.outcome).toBe("pending");
      expect(receipt.actor_ref).toBe(agent.principalRef);
    };

    // Actor authority is setup, not the standing consent Grant under test.
    // Fresh arbitrary agents have no Auto ceiling; that administrative hold would hide the consent decision.
    const actorPolicy = await engine.client.call("vault.gate.policy.put", {
      manifest: policyManifest("e2e-muse-gate01-actor", "1", [
        { actor_class: "agent", actor_ref: agent.principalRef, ceiling: "auto" },
      ]),
    });
    const actorPolicyReadback = await engine.client.call("vault.gate.policy.get", {
      manifest_ref: actorPolicy.manifest.manifest_ref,
    });
    expect(actorPolicyReadback.manifests[0]?.manifest.actor_ceilings).toEqual([
      { actor_class: "agent", actor_ref: agent.principalRef, ceiling: "auto" },
    ]);

    // P-GATE-002: with no standing Grant, the outbound effect asks, and the
    // attempt leaves a governing receipt for the asking agent.
    stage = "no-grant outbound preflight and held schedule";
    const firstEffect = museGate01Outbound(insideAudience.id_hex);
    expect(await museGate01Can(firstEffect)).toBe("would_ask");
    const receiptsBeforeAsk = await museGate01ReceiptRefs();
    await museGate01ExpectAsk(firstEffect);
    await museGate01ExpectNewReceipt(
      receiptsBeforeAsk,
      agent.principalRef,
      "receipt for the no-grant outbound ask",
    );

    // The registry begins without a row for this class.
    const registryBeforeCreate = await engine.client.call("vault.consent.registry", {
      limit: 100,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(registryBeforeCreate.rows.some((row) => row.class === className)).toBe(false);

    // P-GATE-002, P-GATE-003 and P-GATE-010: only the paired owner's
    // yes creates the bounded actor x class x envelope Grant.
    stage = "owner standing action grant and registry readback";
    const standingRequest = {
      bound: {
        actor: agent.principalRef,
        class: className,
        envelope: { project, audience: [insideAudience.id_hex] },
      },
    } satisfies FacadeInput<"vault.consent.create_standing_grant">;
    const created = await engine.client.call(
      "vault.consent.create_standing_grant",
      standingRequest,
    );
    if (!created.grant_ref) throw new Error("Standing grant receipt has no grant reference");
    const grantRef = created.grant_ref;

    const museGate01RegistryRow = async (includeRevoked: boolean) => {
      const query: FacadeInput<"vault.consent.registry"> = includeRevoked
        ? { limit: 100, include_revoked: true } : { limit: 100 };
      const registry = await engine.client.call("vault.consent.registry", query);
      return registry.rows.find((row) => row.grant_ref === grantRef);
    };
    const liveRow = await museGate01RegistryRow(false);
    if (!liveRow) throw new Error("Consent registry does not read the new standing grant back");
    expect(liveRow.domain).toBe("action");
    expect(liveRow.subject).toBe(agent.principalRef);
    expect(liveRow.class).toBe(className);
    expect(liveRow.revoke_action.grant_ref).toBe(grantRef);
    expect(liveRow.revoke_action.command.length).toBeGreaterThan(0);
    const liveSelectors = liveRow.selectors;
    await engine.artifacts.json("muse-gate01-grant-registry.json", {
      created, liveRow, project, classRow,
    });

    // Full-door rule: a live Grant survives restart and reads back unchanged.
    await engine.restart();
    const afterRestartRow = await museGate01RegistryRow(false);
    if (!afterRestartRow) throw new Error("Consent registry lost the live grant across restart");
    expect(afterRestartRow.subject).toBe(agent.principalRef);
    expect(afterRestartRow.class).toBe(className);
    expect(afterRestartRow.selectors).toEqual(liveSelectors);

    // P-GATE-003: two distinct effects inside actor, class and envelope
    // both run without a fresh ask. The second actual schedule leaves its
    // gate decision and a read-back governing receipt.
    stage = "in-grant outbound reuse";
    const reuseOne = museGate01Outbound(insideAudience.id_hex);
    const reuseTwo = museGate01Outbound(insideAudience.id_hex);
    expect(reuseOne.idempotency_key).not.toBe(reuseTwo.idempotency_key);
    expect(await museGate01Can(reuseOne)).toBe("allow");
    expect(await museGate01Can(reuseTwo)).toBe("allow");
    const allowedOne = await agent.client.call("connector.outbound.schedule", reuseOne);
    expect(allowedOne.gate_outcome).toBe("allow");
    if (!allowedOne.gate_decision_ref) throw new Error("First in-grant schedule has no Gate decision");
    expect((await gateReceipt(engine, `gate:${allowedOne.gate_decision_ref.replace(/^gate:/, "")}`)).outcome)
      .toBe("allow");
    const receiptsBeforeAllowed = await museGate01ReceiptRefs();
    const allowed = await agent.client.call("connector.outbound.schedule", reuseTwo);
    expect(allowed.gate_outcome).toBe("allow");
    expect(allowed.intent_ref.length).toBeGreaterThan(0);
    if (!allowed.gate_decision_ref) {
      throw new Error("Allowed outbound schedule has no gate decision receipt");
    }
    expect(allowed.gate_decision_ref.length).toBeGreaterThan(0);
    await museGate01ExpectNewReceipt(
      receiptsBeforeAllowed,
      agent.principalRef,
      "receipt for the in-grant outbound schedule",
    );

    // P-GATE-004: another audience exceeds the envelope, so there is a
    // fresh ask, and reuse has not silently widened the Grant row.
    stage = "outside-audience outbound ask";
    const exceedingEffect = museGate01Outbound(outsideAudience.id_hex);
    expect(await museGate01Can(exceedingEffect)).toBe("would_ask");
    await museGate01ExpectAsk(exceedingEffect);
    const afterExceedRow = await museGate01RegistryRow(false);
    if (!afterExceedRow) throw new Error("Consent registry lost the grant after an exceeding effect");
    expect(afterExceedRow.subject).toBe(agent.principalRef);
    expect(afterExceedRow.class).toBe(className);
    expect(afterExceedRow.selectors).toEqual(liveSelectors);

    // The wrong actor kind cannot mint the same Grant for itself, nor
    // revoke the owner's Grant. The mint refusal leaves a receipt and the
    // registry remains exactly the grant the owner created.
    stage = "agent mint and revoke refusals";
    const agentMint = await agent.client.raw(
      "POST",
      "/v1/core/facade/vault.consent.create_standing_grant",
      standingRequest satisfies FacadeInput<"vault.consent.create_standing_grant">,
    );
    expect(agentMint.status).toBeGreaterThanOrEqual(400);
    expect(agentMint.status).not.toBe(202);
    const mintError = museGate01Error(agentMint.body);
    if (!mintError) throw new Error("Agent self-grant refusal has no standard error envelope");
    expect(mintError.code.length).toBeGreaterThan(0);
    expect(mintError.message.length).toBeGreaterThan(0);
    const mintReceiptRef = new PublicHttpError(agentMint).error?.receiptRef;
    if (typeof mintReceiptRef !== "string") throw new Error("Agent self-grant refusal has no receiptRef");
    await engine.awaitReceipt(mintReceiptRef);

    // The grantee may renounce its own Grant (P-GATE-010); the wrong actor here is a non-grantee.
    const agentRevoke = await otherAgent.client.raw(
      "POST",
      "/v1/core/facade/vault.consent.revoke",
      { grant: grantRef } satisfies FacadeInput<"vault.consent.revoke">,
    );
    expect(agentRevoke.status).toBeGreaterThanOrEqual(400);
    expect(agentRevoke.status).not.toBe(202);
    const revokeError = museGate01Error(agentRevoke.body);
    if (!revokeError) throw new Error("Agent revoke refusal has no standard error envelope");
    expect(revokeError.code.length).toBeGreaterThan(0);
    expect(revokeError.message.length).toBeGreaterThan(0);
    expect(await museGate01RegistryRow(false)).toBeDefined();
    const registryAfterAgentActs = await engine.client.call("vault.consent.registry", {
      limit: 100,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(registryAfterAgentActs.rows.filter((row) => row.class === className))
      .toHaveLength(1);

    // P-GATE-010: the owner revokes in one registry call. The row leaves
    // the live registry but stays visible when revoked grants are included.
    stage = "owner revoke and next-use ask";
    const revoked = await engine.client.call("vault.consent.revoke", {
      grant: grantRef,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect(await museGate01RegistryRow(false)).toBeUndefined();
    const revokedRow = await museGate01RegistryRow(true);
    if (!revokedRow) throw new Error("Revoked grant vanished from the audit registry");
    expect(revokedRow.class).toBe(className);
    await engine.artifacts.json("muse-gate01-revoke.json", {
      allowed, revoked, revokedRow,
    });

    // Owner 9 Nov substrate ruling: an agent that loses the Grant mid-flow
    // asks (and is therefore not allowed) at its next use.
    const afterRevokeEffect = museGate01Outbound(insideAudience.id_hex);
    expect(await museGate01Can(afterRevokeEffect)).toBe("would_ask");
    await museGate01ExpectAsk(afterRevokeEffect);
  } catch (error) {
    const detail = error instanceof PublicHttpError
      ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
      : error instanceof Error ? error.message : String(error);
    if (stage === "no-grant outbound preflight and held schedule") {
      throw new Error(`MUSE-GATE-01 ENGINE DEFECT 2026-11-11: P-GATE-002 / DEC-0006 invariant 1 requires the ungranted irreversible send to ask; can(outbound_schedule) instead names missing external-effect authority as an administrative hold because a non-mail send's owner press cannot supply that authority (FIX 22102; separate from later FIX 7950/11874 bound mismatch); ${stage}; last can=${JSON.stringify(lastCan)}; ${detail}`, { cause: error });
    }
    if (stage === "in-grant outbound reuse") {
      throw new Error(`MUSE-GATE-01 ENGINE DEFECT 2026-11-11: generic action Grant's facade verb class and project/audience envelope do not cover the schedule's send/verb:send/channel requirement (P-GATE-003; FIX 7950/11874); ${stage}; last can=${JSON.stringify(lastCan)}; ${detail}`, { cause: error });
    }
    throw new Error(`MUSE-GATE-01 ${stage}: ${detail}`, { cause: error });
  } finally {
    await engine.close();
  }
});

interface museGate02MaskFixture {
  occurredAt: number;
  agentName: string;
  prefix: string;
  suffix: string;
  textHandleTemplate: string;
  credential: string;
  agentReason: string;
}

type museGate02AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museGate02RegistryRow = FacadeResult<"vault.consent.registry">["rows"][number];
type museGate02RevealAsk = FacadeResult<"vault.disclosure.reveals">[number];
type museGate02Outcome = FacadeInput<"vault.disclosure.reveals.answer">["outcome"];

function museGate02Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museGate02NoSecret(value: unknown, secret: string): void {
  const text = JSON.stringify(value) ?? "";
  const encoded = Buffer.from(secret).toString("base64");
  // Boolean assertions keep the generated credential out of diagnostics.
}

function museGate02HasValue(
  answer: FacadeResult<"reveal.wait">,
  secret: string,
): boolean {
  const encoded = Buffer.from(secret).toString("base64");
  return answer.value === secret || answer.value === encoded
    || answer.value_base64 === secret || answer.value_base64 === encoded;
}

async function museGate02Refused403(run: () => Promise<unknown>): Promise<void> {
  let refused: PublicHttpError | undefined;
  try {
    await run();
  } catch (error) {
    if (error instanceof PublicHttpError) refused = error;
    else throw error;
  }
  if (!refused) throw new Error("Wrong-actor call was not refused");
  expect(refused.reply.status).toBe(403);
  expect(typeof refused.error?.code).toBe("string");
  expect((refused.error?.code ?? "").length).toBeGreaterThan(0);
  expect(typeof refused.error?.message).toBe("string");
  expect((refused.error?.message ?? "").length).toBeGreaterThan(0);
}

async function museGate02PendingAsk(
  engine: EngineFixture,
  reveal: string,
): Promise<museGate02RevealAsk> {
  const rows = await awaitPublic(
    () => engine.client.call("vault.disclosure.reveals", {
      pending: true,
    } satisfies FacadeInput<"vault.disclosure.reveals">),
    (asks) => asks.some((row) => row.receipt.reveal === reveal),
    { label: `pending reveal ask ${reveal}`, timeoutMs: LIMITS.requestMs },
  );
  const row = rows.find((ask) => ask.receipt.reveal === reveal);
  if (!row?.expected_digest) throw new Error("Public pending reveal lacks its consent digest");
  return row;
}

async function museGate02OpenPendingAsk(
  client: PublicHttpClient,
  handle: string,
  why: string,
  secret: string,
): Promise<FacadeResult<"reveal">> {
  const pending = await client.call("reveal", {
    handle, why,
  } satisfies FacadeInput<"reveal">);
  const waiting = await client.call("reveal.wait", {
    reveal: pending.reveal,
  } satisfies FacadeInput<"reveal.wait">);
  expect(waiting.decision).toBe("pending");
  expect(waiting.value == null && waiting.value_base64 == null).toBe(true);
  museGate02NoSecret(waiting, secret);
  return pending;
}

async function museGate02Answer(
  engine: EngineFixture,
  reveal: string,
  outcome: museGate02Outcome,
): Promise<FacadeResult<"vault.disclosure.reveals.answer">> {
  const ask = await museGate02PendingAsk(engine, reveal);
  const digest = ask.expected_digest;
  if (!digest) throw new Error("Public pending reveal lacks its consent digest");
  const answered = await engine.client.call("vault.disclosure.reveals.answer", {
    reveal, expected_digest: digest, outcome,
  } satisfies FacadeInput<"vault.disclosure.reveals.answer">);
  expect(answered.reveal).toBe(reveal);
  expect(answered.outcome).toBe(outcome);
  expect(answered.receipt_ref.length).toBeGreaterThan(0);
  await engine.awaitReceipt(answered.receipt_ref);
  return answered;
}

async function museGate02WaitGranted(
  client: PublicHttpClient,
  reveal: string,
  handle: string,
  why: string,
  secret: string,
): Promise<FacadeResult<"reveal.wait">> {
  const answer = await client.call("reveal.wait", {
    reveal,
  } satisfies FacadeInput<"reveal.wait">);
  expect(answer.decision).toBe("granted");
  expect(museGate02HasValue(answer, secret)).toBe(true);
  expect(answer.receipt?.handle).toBe(handle);
  expect(answer.receipt?.why).toBe(why);
  museGate02NoSecret(answer.receipt, secret);
  return answer;
}

async function museGate02WaitDenied(
  client: PublicHttpClient,
  reveal: string,
  handle: string,
  why: string,
  secret: string,
): Promise<FacadeResult<"reveal.wait">> {
  const answer = await client.call("reveal.wait", {
    reveal,
  } satisfies FacadeInput<"reveal.wait">);
  expect(answer.decision).toBe("denied");
  expect(answer.value == null && answer.value_base64 == null).toBe(true);
  expect(answer.receipt?.handle).toBe(handle);
  expect(answer.receipt?.why).toBe(why);
  museGate02NoSecret(answer, secret);
  return answer;
}

async function museGate02Registry(
  engine: EngineFixture,
  includeRevoked = false,
): Promise<FacadeResult<"vault.consent.registry">> {
  const query: FacadeInput<"vault.consent.registry"> = includeRevoked
    ? { limit: 500, include_revoked: true } : { limit: 500 };
  return engine.client.call("vault.consent.registry", query);
}

async function museGate02RegistryRefs(
  engine: EngineFixture,
  includeRevoked = false,
): Promise<string[]> {
  const registry = await museGate02Registry(engine, includeRevoked);
  return registry.rows.map((row) => row.grant_ref).sort();
}

async function museGate02FindRegistryRow(
  engine: EngineFixture,
  grantRef: string,
): Promise<museGate02RegistryRow> {
  const registry = await awaitPublic(
    () => museGate02Registry(engine),
    (value) => value.rows.some((row) => row.grant_ref === grantRef),
    { label: `consent registry row ${grantRef}`, timeoutMs: LIMITS.requestMs },
  );
  const row = registry.rows.find((candidate) => candidate.grant_ref === grantRef);
  if (!row) throw new Error("Consent registry lost a row it just reported");
  return row;
}

async function museGate02AuditRows(
  engine: EngineFixture,
): Promise<museGate02AuditRow[]> {
  const rows: museGate02AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500, ...(after ? { after } : {}),
    };
    const page = await engine.client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museGate02AuditLinks(
  row: museGate02AuditRow,
  grantRef: string,
  receiptRef?: string,
): boolean {
  return row.grant_ref === grantRef
    || (row.affected_grants?.includes(grantRef) ?? false)
    || (receiptRef !== undefined && row.receipt_ref === receiptRef);
}

async function museGate02AwaitAudit(
  engine: EngineFixture,
  label: string,
  match: (row: museGate02AuditRow) => boolean,
): Promise<museGate02AuditRow> {
  const rows = await awaitPublic(
    () => museGate02AuditRows(engine),
    (value) => value.some(match),
    { label, timeoutMs: LIMITS.requestMs },
  );
  const row = rows.find(match);
  if (!row) throw new Error("Authority audit lost a row it just reported");
  return row;
}

// MUSE-GATE-02 - P-GATE-007, P-GATE-008, P-GATE-009, proved on DEC-0006's
// worked reveal instance (DEC-0006 #model-connection; ARCH-0069 #reveal-check).
// Doors used: an agent's reveal/reveal.wait/reveal.describe; the owner's
// vault.disclosure.reveals and vault.disclosure.reveals.answer (outcomes
// "once" | "standing" | "deny"); read back through vault.consent.registry,
// vault.authority.audit and engine.awaitReceipt; revoked through
// vault.consent.revoke. One restart sits between the standing grant's reuse
// and its revocation, so the same agent loses the grant mid-flow.
// P-GATE-010 (reworded): the issuer revokes with a receipt; the grantee
// may drop its own grant with no ask.
// What stays unproved: the same trio on action and foreign-actor
// scope-exceed confirmations (ARCH-0072 #living), the generic effect-digest
// doors (vault.consent.approve_once / deny / create_standing_grant) with a
// live held action effect, and any direct read of an asking fork's slip.
// Approve-once's fork bound is proved by behaviour: the next distinct ask
// is pending again and the registry gains no row.
suite.test(test, "MUSE-GATE-02", "A reveal confirmation offers approve once, approve-and-stop-asking and deny, and each does only what it says", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<museGate02MaskFixture>("secrets-mask-on-write");
  redactor.add(fixture.credential, Buffer.from(fixture.credential).toString("base64"));
  const engine = await EngineFixture.start({ id: "MUSE-GATE-02", profile });
  let stage = "witness and masked MESSAGE readback";
  try {
    // Two paired agents: the asker whose lineage can hold the standing
    // grant, and another agent who never receives it.
    const askerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: fixture.agentName }, occurred_at: fixture.occurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const otherRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: `${fixture.agentName} Other` }, occurred_at: fixture.occurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const asker = await engine.pairActor({
      principalRef: askerRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const other = await engine.pairActor({
      principalRef: otherRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    for (const record of [askerRecord, otherRecord]) {
      expect((await engine.client.call("vault.get", { entity_ref: record.entity_ref })).value?.id_hex)
        .toBe(record.id_hex);
    }
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [engine.pairedActor.principalRef, asker.principalRef, other.principalRef] },
      occurred_start: fixture.occurredAt, occurred_end: fixture.occurredAt,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: fixture.occurredAt,
      messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
        content: fixture.prefix + fixture.credential + fixture.suffix }],
    } satisfies FacadeInput<"vault.witness">);
    const savedTurn = await engine.client.call("vault.get", {
      entity_ref: witnessed.turn_id,
    } satisfies FacadeInput<"vault.get">);
    expect(savedTurn.value?.id_hex).toBe(witnessed.turn_id);
    expect(witnessed.message_short_ids.length).toBe(1);
    const messageRef = witnessed.message_short_ids[0];
    if (!messageRef) throw new Error("Witness returned no message reference");
    const saved = await engine.client.call("vault.get", {
      entity_ref: messageRef,
    } satisfies FacadeInput<"vault.get">);
    if (!saved.value) throw new Error("Witnessed message is not publicly readable");
    const content = museGate02Object(saved.value.body).content;
    expect(typeof content).toBe("string");
    const found = String(content).match(/\bsc[0-9]+\b/g) ?? [];
    expect(found.length).toBe(1);
    const handle = found[0];
    if (!handle) throw new Error("Masked message carries no secret handle");
    const masked = fixture.prefix + fixture.textHandleTemplate.replace("{handle}", handle) + fixture.suffix;
    museGate02NoSecret(saved, fixture.credential);

    stage = "reveal.describe without a grant";
    const card = await asker.client.call("reveal.describe", {
      handle,
    } satisfies FacadeInput<"reveal.describe">);
    expect(card.handle).toBe(handle);
    expect(card.reveal).toBe("asks");
    museGate02NoSecret(card, fixture.credential);

    const baselineRefs = await museGate02RegistryRefs(engine);
    const onceWhy = `${fixture.agentReason} muse-gate-02 once`;
    const denyWhy = `${fixture.agentReason} muse-gate-02 second ask`;
    const standingWhy = `${fixture.agentReason} muse-gate-02 stop asking`;
    const reuseWhy = `${fixture.agentReason} muse-gate-02 reuse`;
    const otherWhy = `${fixture.agentReason} muse-gate-02 other agent`;
    const restartWhy = `${fixture.agentReason} muse-gate-02 after restart`;
    const afterRevokeWhy = `${fixture.agentReason} muse-gate-02 after revoke`;
    const afterRenounceWhy = `${fixture.agentReason} muse-gate-02 after renounce`;

    // No grant: the ask is held for the owner and carries no value.
    stage = "approve once and wrong-actor settlement refusal";
    const onceAsk = await museGate02OpenPendingAsk(asker.client, handle, onceWhy, fixture.credential);
    const oncePending = await museGate02PendingAsk(engine, onceAsk.reveal);
    expect(oncePending.receipt.handle).toBe(handle);
    expect(oncePending.receipt.why).toBe(onceWhy);
    museGate02NoSecret(oncePending, fixture.credential);
    const onceDigest = oncePending.expected_digest;
    if (!onceDigest) throw new Error("Public pending reveal lacks its consent digest");

    // The asking lineage never settles its own ask.
    await museGate02Refused403(() => asker.client.call("vault.disclosure.reveals.answer", {
      reveal: onceAsk.reveal, expected_digest: onceDigest, outcome: "once",
    } satisfies FacadeInput<"vault.disclosure.reveals.answer">));
    const stillPending = await museGate02PendingAsk(engine, onceAsk.reveal);
    expect(stillPending.receipt.reveal).toBe(onceAsk.reveal);

    // Approve once: this ask's value, no standing grant, registry unchanged.
    const onceAnswered = await museGate02Answer(engine, onceAsk.reveal, "once");
    expect(onceAnswered.grant_ref ?? null).toBeNull();
    await museGate02WaitGranted(asker.client, onceAsk.reveal, handle, onceWhy, fixture.credential);
    expect(await museGate02RegistryRefs(engine)).toEqual(baselineRefs);

    // The next distinct intent asks again. There is no duration outcome.
    stage = "next distinct ask and deny";
    const denyAsk = await museGate02OpenPendingAsk(asker.client, handle, denyWhy, fixture.credential);
    const denyPending = await museGate02PendingAsk(engine, denyAsk.reveal);
    const denyDigest = denyPending.expected_digest;
    if (!denyDigest) throw new Error("Public pending reveal lacks its consent digest");
    const badOutcome = await engine.client.raw(
      "POST", "/v1/core/facade/vault.disclosure.reveals.answer", {
        reveal: denyAsk.reveal, expected_digest: denyDigest, outcome: "for_one_hour",
      },
    );
    expect(badOutcome.status).toBeGreaterThanOrEqual(400);
    expect(badOutcome.status).toBeLessThan(500);
    museGate02NoSecret(badOutcome.body, fixture.credential);
    const unsettled = await museGate02PendingAsk(engine, denyAsk.reveal);
    expect(unsettled.receipt.reveal).toBe(denyAsk.reveal);

    // Deny: a rejected verdict with a receipt, the row left where it was.
    const denied = await museGate02Answer(engine, denyAsk.reveal, "deny");
    expect(denied.grant_ref ?? null).toBeNull();
    await museGate02WaitDenied(asker.client, denyAsk.reveal, handle, denyWhy, fixture.credential);
    expect(await museGate02RegistryRefs(engine)).toEqual(baselineRefs);

    // Approve and stop asking: a bounded standing grant on the lineage.
    stage = "approve standing and registry/Gate audit readback";
    const standingAsk = await museGate02OpenPendingAsk(asker.client, handle, standingWhy, fixture.credential);
    const standingAnswered = await museGate02Answer(engine, standingAsk.reveal, "standing");
    const standingGrant = standingAnswered.grant_ref
      ?? (await engine.client.call("vault.disclosure.reveals", {
      } satisfies FacadeInput<"vault.disclosure.reveals">))
        .find((row) => row.receipt.reveal === standingAsk.reveal)?.grant_ref
      ?? undefined;
    if (!standingGrant) throw new Error("Approve-and-stop-asking created no observable grant");
    await museGate02WaitGranted(asker.client, standingAsk.reveal, handle, standingWhy, fixture.credential);

    const standingRow = await museGate02FindRegistryRow(engine, standingGrant);
    expect(standingRow.domain).toBe("disclosure");
    expect(standingRow.subject.length).toBeGreaterThan(0);
    expect(standingRow.class.length).toBeGreaterThan(0);
    expect(standingRow.selectors.length > 0 || standingRow.scope != null).toBe(true);
    expect(standingRow.revoke_action.grant_ref).toBe(standingGrant);
    expect(standingRow.revoke_action.command.length).toBeGreaterThan(0);
    museGate02NoSecret(standingRow, fixture.credential);
    const grantAudit = await gateReceipt(engine, standingAnswered.receipt_ref);
    expect(grantAudit.reason_codes).toContain("gate.consent.standing_created");
    expect(grantAudit.actor_ref).toBe(engine.pairedActor.principalRef);
    const standingRefs = await museGate02RegistryRefs(engine);
    expect(standingRefs).toContain(standingGrant);
    await engine.artifacts.json("muse-gate02-standing.json", {
      handle, grant_ref: standingGrant,
      answered_receipt_ref: standingAnswered.receipt_ref,
      registry_row: standingRow, audit_receipt_ref: grantAudit.receipt_ref,
    });

    // Reuse inside the bound hydrates at once and mints nothing new.
    stage = "standing reuse and other-agent bound";
    const reuseAsk = await asker.client.call("reveal", {
      handle, why: reuseWhy,
    } satisfies FacadeInput<"reveal">);
    await museGate02WaitGranted(asker.client, reuseAsk.reveal, handle, reuseWhy, fixture.credential);
    const pendingAfterReuse = await engine.client.call("vault.disclosure.reveals", {
      pending: true,
    } satisfies FacadeInput<"vault.disclosure.reveals">);
    expect(pendingAfterReuse.some((row) => row.receipt.reveal === reuseAsk.reveal)).toBe(false);
    expect(await museGate02RegistryRefs(engine)).toEqual(standingRefs);

    // Bounded to the asking lineage: the other agent still has to ask.
    const otherAsk = await museGate02OpenPendingAsk(other.client, handle, otherWhy, fixture.credential);
    const otherDenied = await museGate02Answer(engine, otherAsk.reveal, "deny");
    expect(otherDenied.grant_ref ?? null).toBeNull();
    await museGate02WaitDenied(other.client, otherAsk.reveal, handle, otherWhy, fixture.credential);

    // The standing grant and its reuse survive a restart.
    stage = "standing grant restart and reuse";
    await engine.restart();
    const rowAfterRestart = await museGate02FindRegistryRow(engine, standingGrant);
    expect(rowAfterRestart.grant_ref).toBe(standingGrant);
    const afterRestartAsk = await asker.client.call("reveal", {
      handle, why: restartWhy,
    } satisfies FacadeInput<"reveal">);
    await museGate02WaitGranted(asker.client, afterRestartAsk.reveal, handle, restartWhy, fixture.credential);
    const pendingAfterRestart = await engine.client.call("vault.disclosure.reveals", {
      pending: true,
    } satisfies FacadeInput<"vault.disclosure.reveals">);
    expect(pendingAfterRestart.some((row) => row.receipt.reveal === afterRestartAsk.reveal)).toBe(false);

    // The issuer (the owner, whose yes created the grant) revokes in the
    // registry with a receipt: gone from the live registry, kept in its
    // history and authority audit, and the asker's next use asks again.
    stage = "issuer revoke and next-use ask";
    const revoked = await engine.client.call("vault.consent.revoke", {
      grant: standingGrant,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect(revoked).toMatchObject({ outcome: "revoked", reason_code: "gate.consent.revoked" });
    const activeAfterRevoke = await museGate02Registry(engine);
    expect(activeAfterRevoke.rows.some((row) => row.grant_ref === standingGrant)).toBe(false);
    expect(await museGate02RegistryRefs(engine)).toEqual(baselineRefs);
    const allAfterRevoke = await museGate02Registry(engine, true);
    expect(allAfterRevoke.rows.some((row) => row.grant_ref === standingGrant)).toBe(true);
    if (!revoked.decision_ref) throw new Error("Owner revoke returned no Gate decision");
    const revokeAudit = await gateReceipt(engine, `gate:${revoked.decision_ref}`);
    expect(revokeAudit.reason_codes).toContain("gate.consent.revoked");
    expect(revokeAudit.actor_ref).toBe(engine.pairedActor.principalRef);

    const afterRevokeAsk = await museGate02OpenPendingAsk(asker.client, handle, afterRevokeWhy, fixture.credential);
    // The grantee may drop its own Grant at any time, with no ask (a narrowing, P-GATE-010).
    const renewedAnswered = await museGate02Answer(engine, afterRevokeAsk.reveal, "standing");
    const renewedGrant = renewedAnswered.grant_ref
      ?? (await engine.client.call("vault.disclosure.reveals", {
      } satisfies FacadeInput<"vault.disclosure.reveals">))
        .find((row) => row.receipt.reveal === afterRevokeAsk.reveal)?.grant_ref
      ?? undefined;
    if (!renewedGrant) throw new Error("Approve-and-stop-asking after revoke created no observable grant");
    // grant_ref is the bound digest; the same bound re-issues the same registry key.
    expect(renewedGrant).toBe(standingGrant);
    expect(renewedAnswered.receipt_ref).not.toBe(standingAnswered.receipt_ref);
    const renewedRow = await museGate02FindRegistryRow(engine, renewedGrant);
    expect(renewedRow.status).toBe("active");
    await museGate02WaitGranted(asker.client, afterRevokeAsk.reveal, handle, afterRevokeWhy, fixture.credential);
    // The asker renounces its own grant: the call lands (no 403, no 202 ask), with the revoke receipt.
    stage = "grantee renounce (check 2)";
    const renounced = await asker.client.call("vault.consent.revoke", {
      grant: renewedGrant,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect(renounced).toMatchObject({ outcome: "revoked", reason_code: "gate.consent.revoked" });
    const activeAfterRenounce = await museGate02Registry(engine);
    expect(activeAfterRenounce.rows.some((row) => row.grant_ref === renewedGrant)).toBe(false);
    expect(await museGate02RegistryRefs(engine)).toEqual(baselineRefs);
    // The grant stops reading: the asker's next use asks again.
    stage = "next use after grantee renounce";
    const afterRenounceAsk = await museGate02OpenPendingAsk(asker.client, handle, afterRenounceWhy, fixture.credential);
    const finalDenied = await museGate02Answer(engine, afterRenounceAsk.reveal, "deny");
    await museGate02WaitDenied(asker.client, afterRenounceAsk.reveal, handle, afterRenounceWhy, fixture.credential);

    await engine.artifacts.json("muse-gate02-summary.json", {
      handle, grant_ref: standingGrant,
      once_receipt_ref: onceAnswered.receipt_ref,
      deny_receipt_ref: denied.receipt_ref,
      standing_receipt_ref: standingAnswered.receipt_ref,
      revoke_outcome: revoked.outcome,
      renewed_grant_ref: renewedGrant, renounce_outcome: renounced.outcome,
      grant_audit_receipt_ref: grantAudit.receipt_ref,
      revoke_audit_receipt_ref: revokeAudit.receipt_ref,
      final_deny_receipt_ref: finalDenied.receipt_ref,
    });
  } catch (error) {
    const detail = error instanceof PublicHttpError
      ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
      : error instanceof Error ? error.message : String(error);
    if (stage === "grantee renounce (check 2)") {
      throw new Error(`MUSE-GATE-02 ENGINE DEFECT 2026-11-11: vault.consent.revoke is owner-only and refuses the grantee's no-ask narrowing (P-GATE-010; prior MUSE-GATE-02-REVOKE study); ${stage}; ${detail}`, { cause: error });
    }
    throw new Error(`MUSE-GATE-02 ${stage}: ${detail}`, { cause: error });
  } finally {
    await engine.close();
  }
});

// MUSE-GATE-03 (PARTIAL)
// Promises:
// - P-GATE-001: a reversible operation runs automatically within its
//   authority unless its capability is configured otherwise.
// - P-GATE-005: a verb outside the slip's class raises an ask rather than
//   failing silently.
// Doors used: owner `vault.structural.put` + `EngineFixture.pairActor` to
// make two agent slips (read+write and read-only); owner
// `vault.gate.policy.get`/`vault.gate.policy.put` for the agent's write
// ceiling and its explicit observed-source auto permit; MCP
// `tools/list`/`tools/call` for `vault.claims.upsert`; owner HTTP
// `vault.claims.list`, `vault.writes.pending`, `vault.receipts`,
// `vault.receipts.get`, `vault.claims.history` and agent HTTP
// `vault.claims.retract` as read-back / undo doors; `engine.restart()`.
// What this subset does NOT prove: Dec-0006's outbound MCP-connector
// capability rows (`always_ask`/`never_allow` on a foreign connector
// slate), a named owner verb-class row stored on a paired slip and its
// pack-drift delta slate, or answering the raised ask and replaying the
// saved call. No harness door found can bind a named verb class to a
// paired MCP actor, and `vault.writes.pending` rows expose no
// effect_digest for `vault.consent.approve_once`. See the report.
const museGate03Occurred = 1769947200;
const museGate03Sentinels = {
  control: "muse-gate03 owner control note",
  before: "muse-gate03 before-grant note",
  granted: "muse-gate03 granted note",
  outside: "muse-gate03 outside-read-slip note",
  revoked: "muse-gate03 after-revoke note",
} as const;
const museGate03Predicates = {
  control: "muse_gate03_control_note",
  before: "muse_gate03_before_grant_note",
  granted: "muse_gate03_granted_note",
  outside: "muse_gate03_outside_note",
  revoked: "muse_gate03_after_revoke_note",
} as const;

type museGate03ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
type museGate03PendingRow = FacadeResult<"vault.writes.pending">[number];
type museGate03ManifestView = FacadeResult<"vault.gate.policy.get">["manifests"][number];
type museGate03Manifest = FacadeInput<"vault.gate.policy.put">["manifest"];
type museGate03Ceiling = museGate03Manifest["actor_ceilings"][number]["ceiling"];
type museGate03SourceTrust = NonNullable<museGate03Manifest["source_trust"]>[string];

interface museGate03McpAttempt {
  readonly outcome: "result" | "rpc-error" | "http-error";
  readonly value: unknown;
}
interface museGate03ErrorEnvelope {
  error?: {
    code?: unknown;
    message?: unknown;
    requestId?: unknown;
    receiptRef?: unknown;
    suggestions?: unknown;
  };
}

function museGate03Record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function museGate03McpIsError(value: unknown): boolean {
  const row = museGate03Record(value);
  if (!row) return false;
  if (row.isError === true) return true;
  if (row.error != null) return true;
  const structured = museGate03Record(row.structuredContent);
  return structured?.error != null;
}

async function museGate03MakeAgent(
  engine: EngineFixture,
  name: string,
  scope: readonly string[],
): Promise<PairedActor> {
  const record = await engine.client.call("vault.structural.put", {
    kind: "PERSON",
    body: { name },
    occurred_at: museGate03Occurred,
  } satisfies FacadeInput<"vault.structural.put">);
  return engine.pairActor({
    principalRef: record.id_hex,
    actorClass: "agent",
    scope,
  });
}

// Discover the tool-first argument wrapper from the tool's own public
// schema instead of guessing it: GATE-01's design note records
// `arguments.spec` for this tool on an older binding, so "spec" is also
// the fallback when the schema is not a plain properties object.
async function museGate03DiscoversUpsertWrap(agent: PairedActor): Promise<{ wrapInSpec: boolean; schemaVersion: string }> {
  const listed = await agent.mcp.listTools();
  const listedRecord = museGate03Record(listed);
  const rawTools = Array.isArray(listed) ? listed : listedRecord?.tools;
  const tools = Array.isArray(rawTools)
    ? rawTools.flatMap((tool) => {
        const row = museGate03Record(tool);
        return row ? [row] : [];
      })
    : [];
  const tool = tools.find((row) => row.name === "vault.claims.upsert");
  if (!tool) {
    throw new Error("MCP tools/list does not expose vault.claims.upsert");
  }
  const schema = museGate03Record(tool.inputSchema) ?? museGate03Record(tool.input_schema);
  const properties = museGate03Record(schema?.properties);
  const schemaVersion = museGate03Record(properties?.schema_version)?.const;
  if (typeof schemaVersion !== "string") {
    throw new Error("MUSE-GATE-03 tools/list omits schema_version.const for vault.claims.upsert");
  }
  const argumentsSchema = museGate03Record(properties?.arguments);
  const argumentProperties = museGate03Record(argumentsSchema?.properties);
  return {
    wrapInSpec: !(argumentProperties && "predicate" in argumentProperties && !("spec" in argumentProperties)),
    schemaVersion,
  };
}

async function museGate03McpUpsert(
  agent: PairedActor,
  input: FacadeInput<"vault.claims.upsert">,
  toolSchema: { wrapInSpec: boolean; schemaVersion: string },
): Promise<museGate03McpAttempt> {
  try {
    const value = await agent.mcp.callTool(
      "vault.claims.upsert",
      {
        schema_version: toolSchema.schemaVersion,
        consent: { policy_ref: "policy:muse-gate03-session", purpose: "MUSE-GATE-03 reversible claim write" },
        arguments: toolSchema.wrapInSpec ? { spec: input } : input,
      },
    );
    return { outcome: "result", value };
  } catch (error) {
    if (error instanceof McpRpcError) {
      return { outcome: "rpc-error", value: error.response };
    }
    if (error instanceof PublicHttpError) {
      return { outcome: "http-error", value: {
        stage: "vault.claims.upsert via MCP", status: error.reply.status,
        code: error.error?.code ?? "<none>", message: error.error?.message ?? "<none>",
        suggestion: error.error?.suggestions?.[0] ?? "<none>", body: error.reply.body,
      } };
    }
    throw error;
  }
}

async function museGate03ManifestView(
  engine: EngineFixture,
  actorRef: string,
): Promise<museGate03ManifestView> {
  const views = await engine.client.call("vault.gate.policy.get", {
  } satisfies FacadeInput<"vault.gate.policy.get">);
  const owned = views.manifests.find((view) =>
    view.manifest.actor_ceilings.some((row) => row.actor_ref === actorRef)
  );
  const fallback = views.manifests.find((view) =>
    view.manifest_ref === views.default_manifest_ref
  ) ?? views.manifests[0];
  const view = owned ?? fallback;
  if (!view) throw new Error("Gate policy read returned no manifest");
  return view;
}

// Owner-side authority for this agent: a specific actor ceiling plus,
// only in the granted step, an explicit observed-source auto permit for
// that one actor. Tightening and revoking restore the manifest's
// original observed-source row exactly as first read.
async function museGate03SetWriteAuthority(
  engine: EngineFixture,
  actorRef: string,
  actorClass: string,
  ceiling: museGate03Ceiling,
  grantObservedAuto: boolean,
  originalObserved: museGate03SourceTrust | undefined,
): Promise<void> {
  const view = await museGate03ManifestView(engine, actorRef);
  const currentTrust: Record<string, museGate03SourceTrust> =
    view.manifest.source_trust ?? {};
  const trustEntries = Object.entries(currentTrust)
    .filter(([name]) => name !== "observed");
  if (grantObservedAuto) {
    const row: museGate03SourceTrust = {
      actor_ref: actorRef,
      max_auto_sensitivity: "restricted",
      auto: true,
      receipted: true,
    };
    trustEntries.push(["observed", row]);
  } else if (originalObserved !== undefined) {
    trustEntries.push(["observed", originalObserved]);
  }
  const manifest: museGate03Manifest = {
    ...view.manifest,
    actor_ceilings: [
      ...view.manifest.actor_ceilings.filter((row) => row.actor_ref !== actorRef),
      { actor_class: actorClass, actor_ref: actorRef, ceiling },
    ],
    source_trust: Object.fromEntries(trustEntries),
  };
  const receipt = await engine.client.call("vault.gate.policy.put", {
    manifest_ref: view.manifest_ref,
    expected_body_hash: view.body_hash,
    manifest,
  } satisfies FacadeInput<"vault.gate.policy.put">);
  expect(receipt.manifest.manifest.actor_ceilings.some((row) =>
    row.actor_ref === actorRef && row.ceiling === ceiling
  )).toBe(true);
  const reread = await museGate03ManifestView(engine, actorRef);
  expect(reread.manifest.actor_ceilings.some((row) =>
    row.actor_ref === actorRef && row.ceiling === ceiling
  )).toBe(true);
}

async function museGate03ClaimRows(
  engine: EngineFixture,
  subjectRef: string,
  predicate: string,
): Promise<museGate03ClaimRow[]> {
  const listed = await engine.client.call("vault.claims.list", {
    subject_ref: subjectRef,
    predicate,
    limit: 1000,
  } satisfies FacadeInput<"vault.claims.list">);
  return [...listed.value];
}

async function museGate03PendingRows(
  engine: EngineFixture,
): Promise<museGate03PendingRow[]> {
  return engine.client.call("vault.writes.pending", {
    limit: 1000,
  } satisfies FacadeInput<"vault.writes.pending">);
}

function museGate03ReceiptMatchesClaim(
  receipt: FacadeResult<"vault.receipts">["receipts"][number],
  row: museGate03ClaimRow,
): boolean {
  if (receipt.claim_ref === row.claim_ref) return true;
  if (receipt.claim && row.claim && receipt.claim.id === row.claim.id) return true;
  return Boolean(
    receipt.claim?.short_id && row.short_ref &&
    receipt.claim.short_id === row.short_ref,
  );
}

// P-GATE-001 landed side: the exact claim is publicly listable at the
// same approval the owner's control write received, carries a Gate
// receipt in the receipts page, and is not parked for consent.
async function museGate03ExpectAutoLanded(
  engine: EngineFixture,
  subjectRef: string,
  predicate: string,
  sentinel: string,
  ownerApproval: string,
): Promise<museGate03ClaimRow> {
  const matching = (await museGate03ClaimRows(engine, subjectRef, predicate))
    .filter((row) => row.value === sentinel);
  expect(matching).toHaveLength(1);
  const row = matching[0];
  if (!row) throw new Error("Auto-landed claim row vanished after counting it");
  expect(row.subject_ref).toBe(subjectRef);
  expect(row.predicate).toBe(predicate);
  expect(row.approval).toBe(ownerApproval);
  const pending = await museGate03PendingRows(engine);
  expect(pending.some((parked) => parked.claim_ref === row.claim_ref)).toBe(false);
  const receipts = await engine.client.call("vault.receipts", {
    limit: 1000,
  } satisfies FacadeInput<"vault.receipts">);
  expect(receipts.receipts.some((receipt) =>
    museGate03ReceiptMatchesClaim(receipt, row)
  )).toBe(true);
  return row;
}

// Ask side shared by P-GATE-001's configured-otherwise step and
// P-GATE-005: no Auto-landed row for the sentinel, and a NEW gated
// write is parked for consent (the public pending queue gains a row).
// A silent deny leaves neither a proposed row nor a pending row and
// therefore fails here, as the promise requires.
async function museGate03ExpectAskParked(
  engine: EngineFixture,
  subjectRef: string,
  predicate: string,
  sentinel: string,
  ownerApproval: string,
  pendingBefore: ReadonlySet<string>,
): Promise<museGate03PendingRow[]> {
  const matching = (await museGate03ClaimRows(engine, subjectRef, predicate))
    .filter((row) => row.value === sentinel);
  expect(matching.some((row) => row.approval === ownerApproval)).toBe(false);
  const pendingAfter = await museGate03PendingRows(engine);
  const raised = pendingAfter.filter((row) => !pendingBefore.has(row.decision_ref));
  expect(raised.length).toBeGreaterThanOrEqual(1);
  for (const row of matching) {
    expect(pendingAfter.some((parked) => parked.claim_ref === row.claim_ref))
      .toBe(true);
  }
  return raised;
}

function museGate03ClaimInput(
  subjectRef: string,
  predicate: string,
  value: string,
  source: string,
  scope: FacadeInput<"vault.claims.upsert">["scope"],
): FacadeInput<"vault.claims.upsert"> {
  return {
    predicate,
    subject_ref: subjectRef,
    value,
    confidence: 1,
    source,
    scope,
    occurred_at: museGate03Occurred,
  } satisfies FacadeInput<"vault.claims.upsert">;
}

suite.test(test, "MUSE-GATE-03", "a reversible MCP claim write runs Auto inside an owner-granted ceiling and source permit, parks as a consent ask when proposed-only, outside a read-only slip, and after the grant is revoked", async () => {
  for (const sentinel of Object.values(museGate03Sentinels)) {
    redactor.add(sentinel);
  }
  const engine = await EngineFixture.start({ id: "MUSE-GATE-03", profile });
  let stage = "agent setup and owner control write";
  let lastAttempt: museGate03McpAttempt | undefined;
  try {
    const predicates = {
      control: "profile.muse_gate03.control",
      before: "profile.muse_gate03.before_grant",
      granted: "profile.muse_gate03.granted",
      outside: "profile.muse_gate03.outside",
      revoked: "profile.muse_gate03.after_revoke",
    };    const agents = await enrolAgents(engine, [
      { name: "muse-gate03-main", tier: "full-access" },
      { name: "muse-gate03-outside", tier: "read-only" },
    ]);
    const main = agents[0]!;
    const outside = agents[1]!;
    for (const actor of [main, outside]) {
      expect((await engine.client.call("vault.get", { entity_ref: actor.principalRef })).value?.id_hex)
        .toBe(actor.principalRef);
    }
    const mainSelf = await main.client.call("self.actor", {
    } satisfies FacadeInput<"self.actor">);
    const outsideSelf = await outside.client.call("self.actor", {
    } satisfies FacadeInput<"self.actor">);
    expect(mainSelf.actor_ref.length).toBeGreaterThan(0);
    expect(outsideSelf.actor_ref.length).toBeGreaterThan(0);

    const conversation = await engine.client.call("vault.conversations.create", {
      body: {
        members: [
          engine.pairedActor.principalRef,
          main.principalRef,
          outside.principalRef,
        ],
      },
      occurred_start: museGate03Occurred,
      occurred_end: museGate03Occurred,
      learned_at: museGate03Occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    expect((await engine.client.call("vault.get", { entity_ref: conversation.id })).value?.id_hex)
      .toBe(conversation.id);
    const scope = await ownerBaseClaimScope(
      engine.client,
      engine.pairedActor.principalRef,
    );

    // Owner control: capture the approval string a landed owner claim
    // carries on this build instead of asserting a guessed literal.
    const control = await engine.client.call("vault.claims.upsert",
      museGate03ClaimInput(
        conversation.id,
        predicates.control,
        museGate03Sentinels.control,
        "user_stated",
        scope,
      ));
    await engine.awaitReceipt(control.receipt_ref);
    const ownerApproval = control.approval;
    const controlRow = await museGate03ExpectAutoLanded(
      engine,
      conversation.id,
      predicates.control,
      museGate03Sentinels.control,
      ownerApproval,
    );
    expect(controlRow.approval).toBe(ownerApproval);

    const mainToolSchema = await museGate03DiscoversUpsertWrap(main);
    const outsideToolSchema = await museGate03DiscoversUpsertWrap(outside);

    stage = "Proposed ceiling and MCP baseline ask";
    const initialView = await museGate03ManifestView(engine, mainSelf.actor_ref);
    const originalObserved: museGate03SourceTrust | undefined =
      initialView.manifest.source_trust?.["observed"];
    await engine.artifacts.json("muse-gate03-initial-policy.json", initialView);

    // Proof order, no Auto grant: the owner first fixes this agent at
    // the proposed ceiling with the original source-trust rows, so the
    // baseline does not depend on shipped defaults.
    await museGate03SetWriteAuthority(
      engine,
      mainSelf.actor_ref,
      mainSelf.actor_class,
      "proposed",
      false,
      originalObserved,
    );
    const pendingBeforeBaseline = new Set(
      (await museGate03PendingRows(engine)).map((row) => row.decision_ref),
    );
    const beforeAttempt = await museGate03McpUpsert(main, museGate03ClaimInput(
      conversation.id,
      predicates.before,
      museGate03Sentinels.before,
      "observed",
      scope,
    ), mainToolSchema);
    lastAttempt = beforeAttempt;
    const beforeAsks = await museGate03ExpectAskParked(
      engine,
      conversation.id,
      predicates.before,
      museGate03Sentinels.before,
      ownerApproval,
      pendingBeforeBaseline,
    );
    await engine.artifacts.json("muse-gate03-before-grant.json", {
      attempt: beforeAttempt,
      asks: beforeAsks,
    });

    // Grant: Auto ceiling plus this actor's explicit observed-source
    // auto permit, in one owner policy put, read back by the helper.
    stage = "owner grants Auto ceiling and observed-source permit";
    await museGate03SetWriteAuthority(
      engine,
      mainSelf.actor_ref,
      mainSelf.actor_class,
      "auto",
      true,
      originalObserved,
    );
    stage = "Auto ceiling and observed-source MCP write";
    const grantedAttempt = await museGate03McpUpsert(main, museGate03ClaimInput(
      conversation.id,
      predicates.granted,
      museGate03Sentinels.granted,
      "observed",
      scope,
    ), mainToolSchema);
    lastAttempt = grantedAttempt;
    expect(grantedAttempt.outcome).toBe("result");
    expect(museGate03McpIsError(grantedAttempt.value)).toBe(false);
    let grantedRow = await museGate03ExpectAutoLanded(
      engine,
      conversation.id,
      predicates.granted,
      museGate03Sentinels.granted,
      ownerApproval,
    );
    await engine.artifacts.json("muse-gate03-granted.json", {
      attempt: grantedAttempt,
      row: grantedRow,
    });

    // P-GATE-005: a Write-class verb from a read-only slip is outside
    // the slip's class. It must raise an ask, not fail silently.
    stage = "read-only slip outside-class ask";
    const pendingBeforeOutside = new Set(
      (await museGate03PendingRows(engine)).map((row) => row.decision_ref),
    );
    const outsideAttempt = await museGate03McpUpsert(outside, museGate03ClaimInput(
      conversation.id,
      predicates.outside,
      museGate03Sentinels.outside,
      "observed",
      scope,
    ), outsideToolSchema);
    lastAttempt = outsideAttempt;
    expect(
      outsideAttempt.outcome !== "result" ||
      museGate03McpIsError(outsideAttempt.value) ||
      !(await museGate03ClaimRows(engine, conversation.id, predicates.outside))
        .some((row) => row.approval === ownerApproval),
    ).toBe(true);
    const outsideAsks = await museGate03ExpectAskParked(
      engine,
      conversation.id,
      predicates.outside,
      museGate03Sentinels.outside,
      ownerApproval,
      pendingBeforeOutside,
    );
    await engine.artifacts.json("muse-gate03-outside.json", {
      attempt: outsideAttempt,
      asks: outsideAsks,
    });

    // Survive a restart: landed claim, live policy rows and parked
    // consent asks all read back unchanged.
    const heldAskRefs = [...beforeAsks, ...outsideAsks]
      .map((row) => row.decision_ref);
    stage = "claims policy and asks survive restart";
    await engine.restart();
    grantedRow = await museGate03ExpectAutoLanded(
      engine,
      conversation.id,
      predicates.granted,
      museGate03Sentinels.granted,
      ownerApproval,
    );
    const pendingAfterRestart = await museGate03PendingRows(engine);
    for (const heldRef of heldAskRefs) {
      expect(pendingAfterRestart.some((row) => row.decision_ref === heldRef))
        .toBe(true);
    }
    const policyAfterRestart = await museGate03ManifestView(
      engine,
      mainSelf.actor_ref,
    );
    expect(policyAfterRestart.manifest.actor_ceilings.some((row) =>
      row.actor_ref === mainSelf.actor_ref && row.ceiling === "auto"
    )).toBe(true);

    // Wrong actor kind: the granted agent tries to widen the other
    // agent through the owner's policy door. Standard refusal
    // envelope, a refused call receipt read back, no policy change.
    stage = "agent policy widening refusal";
    const attemptView = await museGate03ManifestView(engine, outsideSelf.actor_ref);
    const widenInput = {
      manifest_ref: attemptView.manifest_ref,
      expected_body_hash: attemptView.body_hash,
      manifest: {
        ...attemptView.manifest,
        actor_ceilings: [
          ...attemptView.manifest.actor_ceilings
            .filter((row) => row.actor_ref !== outsideSelf.actor_ref),
          {
            actor_class: outsideSelf.actor_class,
            actor_ref: outsideSelf.actor_ref,
            ceiling: "auto",
          },
        ],
      },
    } satisfies FacadeInput<"vault.gate.policy.put">;
    const refused = await main.client.raw<museGate03ErrorEnvelope>(
      "POST",
      "/v1/core/facade/vault.gate.policy.put",
      widenInput,
    );
    expect(refused.status).toBeGreaterThanOrEqual(400);
    expect(refused.status).toBeLessThan(500);
    const refusalError = refused.body.error;
    if (!refusalError) throw new Error("Refused policy put lacks its error envelope");
    expect(typeof refusalError.code).toBe("string");
    expect(typeof refusalError.message).toBe("string");
    expect(typeof refusalError.receiptRef).toBe("string");
    const refusalCode = refusalError.code;
    const refusalReceiptRef = refusalError.receiptRef;
    if (typeof refusalCode !== "string" || typeof refusalReceiptRef !== "string") {
      throw new Error("Refused policy put lacks code or receipt reference");
    }
    const refusalReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", {
        receipt_ref: refusalReceiptRef,
      } satisfies FacadeInput<"vault.receipts.get">),
      (value) => value !== null,
      { label: "MUSE-GATE-03 refused policy-put call receipt", timeoutMs: LIMITS.requestMs },
    );
    if (!refusalReceipt) throw new Error("Refused policy put has no readable call receipt");
    expect(refusalReceipt.verb).toBe("vault.gate.policy.put");
    if (typeof refusalReceipt.outcome === "string") {
      throw new Error("Refused policy put was receipted as a success");
    }
    expect(refusalReceipt.outcome.refused.code).toBe(refusalCode);
    const policyViewsAfterRefusal = await engine.client.call("vault.gate.policy.get", {
    } satisfies FacadeInput<"vault.gate.policy.get">);
    expect(policyViewsAfterRefusal.manifests.some((view) =>
      view.trusted && view.manifest.actor_ceilings.some((row) =>
        row.actor_ref === outsideSelf.actor_ref && row.ceiling === "auto"
      )
    )).toBe(false);
    await engine.artifacts.json("muse-gate03-policy-refusal.json", {
      status: refused.status,
      receipt: refusalReceipt,
    }, [refusalReceiptRef]);

    // Undo is the net: while the grant still stands, the agent
    // retracts its own landed claim through a second surface; the
    // row changes state and history keeps the original value.
    stage = "agent retracts its own landed claim";
    const lifecycleBeforeUndo = grantedRow.lifecycle;
    const undo = await main.client.call("vault.claims.retract", {
      claim_ref: grantedRow.claim_ref,
    } satisfies FacadeInput<"vault.claims.retract">);
    expect(undo.receipt_ref.length).toBeGreaterThan(0);
    const rowsAfterUndo = await museGate03ClaimRows(
      engine,
      conversation.id,
      predicates.granted,
    );
    expect(rowsAfterUndo.every((row) =>
      row.claim_ref !== grantedRow.claim_ref ||
      row.lifecycle !== lifecycleBeforeUndo
    )).toBe(true);
    const history = await engine.client.call("vault.claims.history", {
      claim_ref: grantedRow.claim_ref,
    } satisfies FacadeInput<"vault.claims.history">);
    expect(history.value.some((row) => row.value === museGate03Sentinels.granted))
      .toBe(true);

    // Revoke mid-flow: the owner takes the Auto ceiling and the
    // observed-source auto permit away through the same door.
    stage = "owner revokes Auto ceiling and observed-source permit";
    await museGate03SetWriteAuthority(
      engine,
      mainSelf.actor_ref,
      mainSelf.actor_class,
      "proposed",
      false,
      originalObserved,
    );
    stage = "revoked ceiling MCP next-use ask";
    const pendingBeforeRevokeUse = new Set(
      (await museGate03PendingRows(engine)).map((row) => row.decision_ref),
    );
    const revokedAttempt = await museGate03McpUpsert(main, museGate03ClaimInput(
      conversation.id,
      predicates.revoked,
      museGate03Sentinels.revoked,
      "observed",
      scope,
    ), mainToolSchema);
    lastAttempt = revokedAttempt;
    const revokedAsks = await museGate03ExpectAskParked(
      engine,
      conversation.id,
      predicates.revoked,
      museGate03Sentinels.revoked,
      ownerApproval,
      pendingBeforeRevokeUse,
    );
    await engine.artifacts.json("muse-gate03-after-revoke.json", {
      attempt: revokedAttempt,
      asks: revokedAsks,
    });
  } catch (error) {
    const detail = error instanceof PublicHttpError
      ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
      : error instanceof Error ? error.message : String(error);
    if (stage === "read-only slip outside-class ask") {
      throw new Error(`MUSE-GATE-03 MISSING DOOR 2026-11-11: a read-only credential is not a named verb-class Grant; its transport refusal cannot prove the P-GATE-005 outside-class consent ask; need a public named-class Grant/slip setup and scope-exceed producer; ${stage}; attempt=${JSON.stringify(lastAttempt)}; ${detail}`, { cause: error });
    }
    throw new Error(`MUSE-GATE-03 ${stage}: ${detail}; last MCP attempt=${JSON.stringify(lastAttempt)}`, { cause: error });
  } finally {
    await engine.close();
  }
});

// MUSE-GATE-04 — P-GATE-011, P-GATE-012, P-GATE-013, P-GATE-014 (partial).
// Doors used: vault.structural.put + pairActor for setup, vault.consent.create_standing_grant,
// vault.consent.bypass_grant_warning, vault.consent.create_bypass_grant, vault.consent.active_bypass_grants,
// vault.consent.registry, vault.consent.revoke, vault.consent.bypassed_effect_receipts, vault.receipts(.get).
// Proved here, at the grant/registry level: a bypass is off by default; its warning grants nothing; creation
// is owner-only and bound to that exact warning; a live bypass reads back active after a restart and ends on
// owner revoke; an ordinary standing grant naming a catastrophe class is refused; a bypass naming the
// agent-widen-world class is refused at warning or creation.
// Unproved (see the report): a real catastrophe effect landing under a live bypass and appearing in
// bypassed_effect_receipts; stop-asking against a live catastrophe ask and the next effect asking again;
// an agent's actual world-settings widen asking a holder despite a live bypass.
// The generated types leave classes/scope as unknown, so the class and scope spellings below are canon's names.

const museGate04OccurredAt = 1769947200;
const museGate04OrdinaryClass = "research.auto_weave";
const museGate04CatastropheStandingClass = "VaultWideDestruction";
const museGate04BypassClasses = ["KeyRecovery", "SecurityControlDisable"] as const;
const museGate04TamperedClass = "MassSecretExport";
const museGate04WidenWorldClass = "WidenWorld";

type museGate04BypassBound = FacadeInput<"vault.consent.bypass_grant_warning">["bound"];
type museGate04ConsentReceipt = FacadeResult<"vault.consent.create_standing_grant">;
type museGate04ActiveState = FacadeResult<"vault.consent.active_bypass_grants">[number];
type museGate04RegistryRow = FacadeResult<"vault.consent.registry">["rows"][number];

interface museGate04Refusal {
  status: number;
  code: string;
  receiptRef: string | null;
}

function museGate04DescribeRefusal(refused: PublicHttpError, label: string): museGate04Refusal {
  const wire = refused.error;
  if (!wire) {
    throw new Error(`${label} refusal has no standard error envelope (HTTP ${refused.reply.status})`);
  }
  expect(wire.code.length).toBeGreaterThan(0);
  expect(wire.message.length).toBeGreaterThan(0);
  const receipt = wire["receiptRef"] ?? wire["receipt_ref"];
  return {
    status: refused.reply.status,
    code: wire.code,
    receiptRef: typeof receipt === "string" && receipt.length > 0 ? receipt : null,
  };
}

async function museGate04RefusalOf(call: Promise<unknown>, label: string): Promise<museGate04Refusal> {
  let refused: PublicHttpError | undefined;
  try {
    await call;
  } catch (error) {
    if (error instanceof PublicHttpError) refused = error;
    else throw error;
  }
  if (!refused) throw new Error(`${label} was not refused`);
  return museGate04DescribeRefusal(refused, label);
}

function museGate04GrantRef(receipt: museGate04ConsentReceipt): string {
  const ref = receipt.grant_ref;
  if (typeof ref !== "string" || ref.length === 0) {
    throw new Error("Consent receipt has no grant reference");
  }
  return ref;
}

function museGate04StatesFor(
  states: readonly museGate04ActiveState[],
  grantRefs: readonly string[],
): museGate04ActiveState[] {
  const wanted = new Set(grantRefs);
  return states.filter((state) => wanted.has(state.grant));
}

function museGate04RowsFor(
  rows: readonly museGate04RegistryRow[],
  grantRefs: readonly string[],
): museGate04RegistryRow[] {
  const wanted = new Set(grantRefs);
  return rows.filter((row) => wanted.has(row.grant_ref));
}

suite.test(test, "MUSE-GATE-04", "A bypass is off by default, only the owner creates it from its scoped warning, and the live bypass reads back active until revoked", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-GATE-04", profile });
  let stage = "off-by-default registry and ordinary Grant";
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const catastropheStandingClass = "vault_wide_destruction";
    const agentName = `MUSE-GATE-04 agent ${secretHex(4)}`;
    redactor.add(agentName);
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: agentName }, occurred_at: museGate04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agentRef = agent.principalRef;
    const otherRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: `${agentName} non-grantee` }, occurred_at: museGate04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const otherAgent = await engine.pairActor({
      principalRef: otherRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    for (const record of [agentRecord, otherRecord]) {
      expect((await engine.client.call("vault.get", { entity_ref: record.entity_ref })).value?.id_hex)
        .toBe(record.id_hex);
    }
    const agentReceipts = await agent.client.call("vault.receipts", {
      limit: 1,
    } satisfies FacadeInput<"vault.receipts">);

    const projectRef = (await ownerBaseClaimScope(engine.client, ownerRef)).scope_project_id;

    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);
    const initialRegistry = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(initialRegistry.rows.every((row) => (row.bypass ?? null) === null)).toBe(true);

    const ordinary = await engine.client.call("vault.consent.create_standing_grant", {
      bound: {
        actor: agentRef, class: museGate04OrdinaryClass,
        envelope: { project: projectRef, audience: [ownerRef] },
      },
    } satisfies FacadeInput<"vault.consent.create_standing_grant">);
    const ordinaryGrantRef = museGate04GrantRef(ordinary);
    const afterOrdinary = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    const ordinaryRows = museGate04RowsFor(afterOrdinary.rows, [ordinaryGrantRef]);
    expect(ordinaryRows).toHaveLength(1);
    expect(ordinaryRows[0]?.class).toBe(museGate04OrdinaryClass);

    stage = "ordinary standing grant rejects catastrophe action class";
    const standingRefusal = await museGate04RefusalOf(
      engine.client.call("vault.consent.create_standing_grant", {
        bound: {
          actor: agentRef, class: catastropheStandingClass,
          envelope: { project: projectRef, audience: [ownerRef] },
        },
      } satisfies FacadeInput<"vault.consent.create_standing_grant">),
      "ordinary standing grant for a catastrophe class",
    );
    const afterStandingAttempt = await engine.client.call("vault.consent.registry", {
      limit: 1000, include_revoked: true,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(afterStandingAttempt.rows.some(
      (row) => row.class === catastropheStandingClass,
    )).toBe(false);
    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);

    await engine.client.call("vault.consent.revoke", {
      grant: ordinaryGrantRef,
    } satisfies FacadeInput<"vault.consent.revoke">);
    const afterOrdinaryRevoke = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(museGate04RowsFor(afterOrdinaryRevoke.rows, [ordinaryGrantRef])).toHaveLength(0);

    stage = "create bypass thread and read it back";
    const thread = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: museGate04OccurredAt,
      occurred_end: museGate04OccurredAt, learned_at: museGate04OccurredAt,
    } satisfies FacadeInput<"vault.conversations.create">);
    const threadReadback = await engine.client.call("vault.get", { entity_ref: thread.id });
    expect(threadReadback.value?.kind).toBe("CONVERSATION");
    expect(threadReadback.value?.id_hex).toBe(thread.id);

    stage = "scoped bypass warning and tampered warning refusal";
    const bypassBound: museGate04BypassBound = {
      actor: agentRef,
      actor_class: "agent",
      classes: [...museGate04BypassClasses],
      scope: { thread: thread.id },
      envelope: { selectors: [`thread:${thread.id}`], target: thread.id, receipt_required: true },
    };
    const warning = await engine.client.call("vault.consent.bypass_grant_warning", {
      bound: bypassBound,
    } satisfies FacadeInput<"vault.consent.bypass_grant_warning">);
    expect(warning.owner).toBe(ownerRef);
    expect(warning.bound.actor).toBe(agentRef);
    expect(warning.bound_digests.length).toBeGreaterThan(0);
    expect(Number.isInteger(warning.floor_version) && warning.floor_version >= 1).toBe(true);
    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);

    const tamperedWarning: FacadeResult<"vault.consent.bypass_grant_warning"> = {
      ...warning,
      bound: {
        ...warning.bound,
        classes: [...museGate04BypassClasses, museGate04TamperedClass],
      },
    };
    const tamperedRefusal = await museGate04RefusalOf(
      engine.client.call("vault.consent.create_bypass_grant", {
        warning: tamperedWarning,
      } satisfies FacadeInput<"vault.consent.create_bypass_grant">),
      "bypass creation from a changed warning",
    );
    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);

    stage = "agent cannot create bypass";
    const agentWarningRefusal = await museGate04RefusalOf(
      agent.client.call("vault.consent.bypass_grant_warning", {
        bound: bypassBound,
      } satisfies FacadeInput<"vault.consent.bypass_grant_warning">),
      "agent bypass warning",
    );
    const agentCreateRefusal = await museGate04RefusalOf(
      agent.client.call("vault.consent.create_bypass_grant", {
        warning,
      } satisfies FacadeInput<"vault.consent.create_bypass_grant">),
      "agent bypass creation",
    );
    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);

    stage = "world privacy widen cannot be bypassed";
    let widenRefusal: museGate04Refusal | undefined;
    try {
      const widenWarning = await engine.client.call("vault.consent.bypass_grant_warning", {
        bound: { ...bypassBound, classes: ["WorldPrivacyWiden"] },
      } satisfies FacadeInput<"vault.consent.bypass_grant_warning">);
      widenRefusal = await museGate04RefusalOf(
        engine.client.call("vault.consent.create_bypass_grant", {
          warning: widenWarning,
        } satisfies FacadeInput<"vault.consent.create_bypass_grant">),
        "bypass creation for an agent widen of a world",
      );
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      widenRefusal = museGate04DescribeRefusal(error, "bypass warning for an agent widen of a world");
    }
    if (!widenRefusal) throw new Error("Bypass for an agent widen of a world was not refused");
    expect(await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">)).toEqual([]);

    stage = "owner creates scoped bypass and reads active state";
    const creationWarning = await engine.client.call("vault.consent.bypass_grant_warning", {
      bound: bypassBound,
    } satisfies FacadeInput<"vault.consent.bypass_grant_warning">);
    expect(creationWarning.owner).toBe(ownerRef);
    const created = await engine.client.call("vault.consent.create_bypass_grant", {
      warning: creationWarning,
    } satisfies FacadeInput<"vault.consent.create_bypass_grant">);
    expect(created).toHaveLength(museGate04BypassClasses.length);
    const grantRefs = created.map((receipt) => museGate04GrantRef(receipt));
    const firstGrantRef = grantRefs[0];
    if (!firstGrantRef) throw new Error("Bypass creation returned no grant reference");

    const activeAfterCreate = await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">);
    const liveStates = museGate04StatesFor(activeAfterCreate, grantRefs);
    expect(liveStates).toHaveLength(grantRefs.length);
    for (const state of liveStates) {
      expect(state.active).toBe(true);
      expect(state.bound.actor).toBe(agentRef);
      expect(state.floor_version).toBe(creationWarning.floor_version);
    }
    const registryAfterCreate = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    const bypassRows = museGate04RowsFor(registryAfterCreate.rows, grantRefs);
    expect(bypassRows).toHaveLength(grantRefs.length);
    for (const row of bypassRows) {
      expect(row.bypass ?? null).not.toBeNull();
    }

    // A non-grantee is the wrong actor; the grantee may renounce under P-GATE-010.
    stage = "non-grantee cannot revoke bypass";
    const agentRevokeRefusal = await museGate04RefusalOf(
      otherAgent.client.call("vault.consent.revoke", {
        grant: firstGrantRef,
      } satisfies FacadeInput<"vault.consent.revoke">),
      "agent bypass revoke",
    );
    const activeAfterAgentRevoke = await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">);
    expect(museGate04StatesFor(activeAfterAgentRevoke, grantRefs)).toHaveLength(grantRefs.length);

    stage = "live bypass survives restart";
    await engine.restart();
    const activeAfterRestart = await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">);
    const restartStates = museGate04StatesFor(activeAfterRestart, grantRefs);
    expect(restartStates).toHaveLength(grantRefs.length);
    for (const state of restartStates) {
      expect(state.active).toBe(true);
    }
    const registryAfterRestart = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(museGate04RowsFor(registryAfterRestart.rows, grantRefs)).toHaveLength(grantRefs.length);

    stage = "owner revokes bypass and reads inactive state";
    for (const grantRef of grantRefs) {
      await engine.client.call("vault.consent.revoke", {
        grant: grantRef,
      } satisfies FacadeInput<"vault.consent.revoke">);
    }
    const activeAfterRevoke = await engine.client.call("vault.consent.active_bypass_grants", {
    } satisfies FacadeInput<"vault.consent.active_bypass_grants">);
    expect(museGate04StatesFor(activeAfterRevoke, grantRefs)).toHaveLength(0);
    const registryAfterRevoke = await engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    expect(museGate04RowsFor(registryAfterRevoke.rows, grantRefs)).toHaveLength(0);
    const registryWithRevoked = await engine.client.call("vault.consent.registry", {
      limit: 1000, include_revoked: true,
    } satisfies FacadeInput<"vault.consent.registry">);
    const revokedRows = museGate04RowsFor(registryWithRevoked.rows, grantRefs);

    await engine.artifacts.json("muse-gate04-bypass.json", {
      projectRef, agentRef, grantRefs,
      standingRefusal, tamperedRefusal, agentWarningRefusal, agentCreateRefusal,
      widenRefusal, agentRevokeRefusal,
      liveStates, restartStates, revokedRows,
    });

    stage = "bypass-creation refusal receipt readback";
    const refusalReceiptRef = agentCreateRefusal.receiptRef;
    if (!refusalReceiptRef) {
      throw new Error("Agent bypass-creation refusal carries no receipt reference");
    }
    const refusalReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", {
        receipt_ref: refusalReceiptRef,
      } satisfies FacadeInput<"vault.receipts.get">),
      (value) => value !== null,
      { label: "agent bypass-creation refusal receipt", timeoutMs: LIMITS.requestMs },
    );
    if (!refusalReceipt) throw new Error("Agent bypass-creation refusal receipt is not readable");
    expect(refusalReceipt.verb).toBe("vault.consent.create_bypass_grant");
    expect(refusalReceipt.actor_ref).toBe(agentRef);
    expect(typeof refusalReceipt.outcome === "object" && "refused" in refusalReceipt.outcome).toBe(true);
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(`MUSE-GATE-04 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error });
    }
    throw new Error(`MUSE-GATE-04 ${stage}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  } finally {
    await engine.close();
  }
});

// MUSE-GATE-05 - A proposer cannot settle or grant its own proposal, and a
// non-holder policy change stays a proposal (PARTIAL).
//
// Promises: P-GATE-015 (the opener's lineage and forks cannot settle their
// own proposal), P-GATE-016 (the opener cannot mint the Grant that answers
// its own proposal), P-GATE-028 (a non-holder's policy change becomes a
// proposal rather than changing effective policy). P-GATE-017 (a received
// peer settlement is data rather than authorization) stays unproved: this
// one-slot file cannot run a same-vault peer, and no typed public sync door
// delivers a peer proposal settlement to a second vault (see the report).
// The true run-fork reading of "forks" in P-GATE-015 also stays unproved:
// no public door in the harness spawns a same-lineage fork actor with its
// own credential. This case does prove the opener itself plus a second,
// independently paired credential for the same opener principal.
//
// Doors used (all public, through engine.client / a paired actor's client):
// vault.conversations.create and vault.structural.put (setup), self.actor,
// vault.scope.ceiling, vault.agents.verb_classes.get/configure,
// vault.claims.seed (open proposals, forced proposed), vault.claims.list and
// vault.writes.pending (second-door reads), vault.claims.review and
// vault.claims.settle (proposal accept/reject), vault.agents.grants.mint and
// .revoke (the answering Grant), vault.consent.create_standing_grant (the
// other mint an opener must not use on itself), vault.consent.registry,
// vault.authority.audit and vault.receipts (second-door read-backs),
// vault.gate.policy.get/propose/put (policy change). Restart via
// engine.restart(). No fixture data: every sentinel is generated here and
// registered with the redactor before first use.
type MuseGate05Client = PairedActor["client"];
type MuseGate05ClaimView = FacadeResult<"vault.claims.list">["value"][number];
type MuseGate05Receipt = FacadeResult<"vault.receipts">["receipts"][number];
type MuseGate05AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type MuseGate05PolicyView = FacadeResult<"vault.gate.policy.get">;
type MuseGate05Manifest = FacadeInput<"vault.gate.policy.propose">["manifest"];
interface MuseGate05Proposal {
  claimRef: string;
  candidates: string[];
  receiptRef: string;
}

// Runs one call that the promise says must be refused, and checks the
// standard refusal envelope (HTTP 4xx/5xx with a coded wire error) instead
// of guessing any single code the canon pages do not name.
async function museGate05Refused(run: () => Promise<unknown>): Promise<PublicHttpError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(PublicHttpError);
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBeGreaterThanOrEqual(400);
    expect(error.reply.status).toBeLessThan(600);
    expect(typeof error.error?.code).toBe("string");
    expect((error.error?.code ?? "").length).toBeGreaterThan(0);
    expect(typeof error.error?.message).toBe("string");
    expect((error.error?.message ?? "").length).toBeGreaterThan(0);
    return error;
  }
  throw new Error("Expected the call to be refused, but it succeeded");
}

async function museGate05PendingRefs(engine: EngineFixture): Promise<string[]> {
  const pending = await engine.client.call("vault.writes.pending", {
    limit: 1000,
  } satisfies FacadeInput<"vault.writes.pending">);
  return pending.map((row) => row.claim_ref);
}

function museGate05IsPending(pendingRefs: readonly string[], candidates: readonly string[]): boolean {
  return candidates.some((candidate) => pendingRefs.includes(candidate));
}

async function museGate05ListedClaim(
  engine: EngineFixture,
  subjectRef: string,
  predicate: string,
  sentinel: string,
): Promise<MuseGate05ClaimView | undefined> {
  const listed = await engine.client.call("vault.claims.list", {
    subject_ref: subjectRef, predicate, limit: 100,
  } satisfies FacadeInput<"vault.claims.list">);
  return listed.value.find((claim) => claim.value === sentinel);
}

async function museGate05RequireListedClaim(
  engine: EngineFixture,
  subjectRef: string,
  predicate: string,
  sentinel: string,
): Promise<MuseGate05ClaimView> {
  const view = await museGate05ListedClaim(engine, subjectRef, predicate, sentinel);
  if (!view) throw new Error("Settled claim is not readable through vault.claims.list");
  return view;
}

// Opens one claim proposal through the public write door (seed is forced
// proposed), then reads it back through two other doors: claims.list for
// the canonical claim ref and writes.pending for the parked state.
async function museGate05SeedProposal(
  engine: EngineFixture,
  client: MuseGate05Client,
  scope: FacadeInput<"vault.claims.seed">["claims"][number]["scope"],
  input: {
    subjectRef: string;
    predicate: string;
    sentinel: string;
    source: string;
    occurredAt: number;
    expectPending?: boolean;
  },
): Promise<MuseGate05Proposal> {
  const outcomes = await client.call("vault.claims.seed", {
    claims: [{
      predicate: input.predicate,
      subject_ref: input.subjectRef,
      value: input.sentinel,
      confidence: 1,
      source: input.source,
      scope,
      occurred_at: input.occurredAt,
    }],
  } satisfies FacadeInput<"vault.claims.seed">);
  expect(outcomes).toHaveLength(1);
  const outcome = outcomes[0]!;
  expect(outcome.outcome).toBe("landed");
  if (outcome.outcome !== "landed") {
    throw new Error("Seeded write was refused instead of parked as a proposal");
  }
  expect(outcome.approval).toBe("proposed");
  expect(outcome.claim_short_id.length).toBeGreaterThan(0);
  expect(outcome.receipt_ref.length).toBeGreaterThan(0);
  await engine.awaitReceipt(outcome.receipt_ref);
  const view = await museGate05ListedClaim(engine, input.subjectRef, input.predicate, input.sentinel);
  if (!view) throw new Error("Parked proposal is not readable through vault.claims.list");
  expect(view.approval).toBe("proposed");
  const candidates = [
    view.claim_ref, outcome.claim_short_id, outcome.claim?.id, outcome.claim?.short_id, view.short_ref,
  ].filter((ref): ref is string => typeof ref === "string" && ref.length > 0);
  if (input.expectPending !== false) expect(museGate05IsPending(await museGate05PendingRefs(engine), candidates)).toBe(true);
  return { claimRef: view.claim_ref, candidates, receiptRef: outcome.receipt_ref };
}

async function museGate05ReceiptRefs(engine: EngineFixture): Promise<Set<string>> {
  const page = await engine.client.call("vault.receipts", {
    limit: 1000,
  } satisfies FacadeInput<"vault.receipts">);
  return new Set(page.receipts.map((row) => row.receipt_ref));
}

// Reads back, through vault.receipts, the new receipt a refusal leaves for
// the parked claim. Repeats a read only; it never retries the refused write.
async function museGate05AwaitClaimReceipt(
  engine: EngineFixture,
  refusal: PublicHttpError,
): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> {
  const receiptRef = refusal.error?.receiptRef;
  if (typeof receiptRef !== "string") throw new Error("Refused settlement has no receiptRef");
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    (value) => value !== null,
    { label: "MUSE-GATE-05 refused settlement call receipt", timeoutMs: LIMITS.requestMs },
  );
  if (!receipt) throw new Error("The refused settlement has no public call receipt");
  expect(receipt.verb).toBe("vault.claims.settle");
  return receipt;
}

async function museGate05AuditRows(engine: EngineFixture): Promise<MuseGate05AuditRow[]> {
  const rows: MuseGate05AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await engine.client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

async function museGate05RegistryRefs(engine: EngineFixture): Promise<Set<string>> {
  const registry = await engine.client.call("vault.consent.registry", {
    limit: 1000,
  } satisfies FacadeInput<"vault.consent.registry">);
  return new Set(registry.rows.map((row) => row.grant_ref));
}

function museGate05CloneManifest(manifest: MuseGate05Manifest): MuseGate05Manifest {
  return JSON.parse(JSON.stringify(manifest)) as MuseGate05Manifest;
}

function museGate05DefaultView(
  view: MuseGate05PolicyView,
): MuseGate05PolicyView["manifests"][number] {
  const found = view.manifests.find((row) => row.manifest_ref === view.default_manifest_ref);
  if (!found) throw new Error("Gate policy read does not contain its default manifest");
  return found;
}

// Effective policy is what a trusted manifest row says. An inert proposal
// (untrusted contribution) must not count, in either direction.
function museGate05TrustedHasAuto(view: MuseGate05PolicyView, actorRefs: readonly string[]): boolean {
  return view.manifests.some((row) => row.trusted
    && row.manifest.actor_ceilings.some((ceiling) => {
      const ref = ceiling.actor_ref;
      return ceiling.ceiling === "auto" && ref != null && actorRefs.includes(ref);
    }));
}

function museGate05TrustedHasRule(view: MuseGate05PolicyView, prefix: string): boolean {
  return view.manifests.some((row) => row.trusted
    && row.manifest.rules.some((rule) => rule.prefix === prefix));
}

suite.test(test, "MUSE-GATE-05", "A proposer cannot settle or grant its own proposal, and a non-holder policy change stays a proposal", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-GATE-05", profile });
  let stage = "principal identity and independent second slip";
  try {
    const occurred = 1769947200;
    const predicateControl = "profile.muse_gate05.control";
    const predicateOwn = "profile.muse_gate05.own";
    const predicateAfterRevoke = "profile.muse_gate05.after_revoke";
    const narrowRulePrefix = "muse_gate05_narrow_probe";
    const holderRulePrefix = "muse_gate05_holder_probe";
    const sentinelControl = `muse-gate05-control-${secretHex(8)}`;
    const sentinelOwn = `muse-gate05-own-${secretHex(8)}`;
    const sentinelAfterRevoke = `muse-gate05-revoked-${secretHex(8)}`;
    redactor.add(sentinelControl, sentinelOwn, sentinelAfterRevoke);

    // Setup: one subject record, and one agent principal paired twice.
    // The two pairings share the opener's principal but hold independent
    // credentials, so the second is the same lineage on a different slip.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const subjectRef = conversation.id;
    const agents = await enrolAgents(engine, [
      { name: "muse-gate05-proposer", tier: "full-access" },
      { name: "muse-gate05-other-proposer", tier: "full-access" },
    ]);
    const agent = agents[0]!;
    const otherProposer = agents[1]!;
    for (const actor of [agent, otherProposer]) {
      expect((await engine.client.call("vault.get", { entity_ref: actor.principalRef })).value?.id_hex)
        .toBe(actor.principalRef);
    }
    expect((await engine.client.call("vault.get", { entity_ref: conversation.id })).value?.id_hex)
      .toBe(conversation.id);
    const agentSecondSlip = await engine.pairActor({
      principalRef: agent.principalRef, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    expect(agentSecondSlip.principalRef).toBe(agent.principalRef);
    expect(agentSecondSlip.credential === agent.credential).toBe(false);
    const ownerRef = engine.pairedActor.principalRef;
    const claimScope = await ownerBaseClaimScope(engine.client, ownerRef);
    const agentSelf = await agent.client.call("self.actor",
      {} satisfies FacadeInput<"self.actor">);
    // person_ref is the person the agent acts for, not the opener's actor lineage.
    expect(agentSelf.actor_ref).toBe(agent.principalRef);
    const agentRefs = [agent.principalRef, agentSelf.actor_ref]
      .filter((ref): ref is string => typeof ref === "string" && ref.length > 0);
    const enrolledPolicy = await engine.client.call("vault.gate.policy.get", {});
    const enrolledManifest = enrolledPolicy.manifests.find(view => view.trusted
      && view.manifest.actor_ceilings.some(row => row.actor_ref === agent.principalRef));
    if (!enrolledManifest) throw new Error("Named agent enrollment has no ceiling manifest");
    await engine.client.call("vault.gate.policy.put", {
      manifest_ref: enrolledManifest.manifest_ref, expected_body_hash: enrolledManifest.body_hash,
      manifest: { ...enrolledManifest.manifest, actor_ceilings: enrolledManifest.manifest.actor_ceilings.map(row =>
        row.actor_ref === agent.principalRef ? { ...row, ceiling: "proposed" as const } : row) },
    });
    const enrolledPolicyReadback = await engine.client.call("vault.gate.policy.get", {});
    expect(museGate05TrustedHasAuto(enrolledPolicyReadback, agentRefs)).toBe(false);
    const ownerSelf = await engine.client.call("self.actor", {} satisfies FacadeInput<"self.actor">);
    expect(agentRefs.includes(ownerSelf.actor_ref)).toBe(false);

    // The verb class that admits vault.claims.settle, read from the owner's
    // own table. If no row names it, the owner adds one row through the
    // public configure door (owner policy, it grants the agent nothing yet).
    const verbClasses0 = await engine.client.call("vault.agents.verb_classes.get",
      {} satisfies FacadeInput<"vault.agents.verb_classes.get">);
    const foundSettleClass = verbClasses0.classes
      .find((row) => row.verbs.includes("vault.claims.settle"))?.name;
    const settleClass = foundSettleClass ?? "muse_gate05_claim_settle";
    if (!foundSettleClass) {
      const configured = await engine.client.call("vault.agents.verb_classes.configure", {
        expected_body_hash: verbClasses0.body_hash,
        classes: [...verbClasses0.classes, { name: settleClass, verbs: ["vault.claims.settle"] }],
      } satisfies FacadeInput<"vault.agents.verb_classes.configure">);
      expect((await museGate05ReceiptRefs(engine)).has(configured.receipt_ref)).toBe(true);
      const verbClasses1 = await engine.client.call("vault.agents.verb_classes.get",
        {} satisfies FacadeInput<"vault.agents.verb_classes.get">);
      expect(verbClasses1.classes.some((row) => row.name === settleClass
        && row.verbs.includes("vault.claims.settle"))).toBe(true);
    }
    // The scope a holder mint is bound to: the owner's own read ceiling.
    const ownerCeiling = await engine.client.call("vault.scope.ceiling",
      {} satisfies FacadeInput<"vault.scope.ceiling">);
    const mintScope = { ...ownerCeiling.scope, verbs: { kind: "some" as const, values: ["read"] } };

    // P-GATE-015, no grant first (F3 order). The agent opens its own claim
    // proposal. Without any settle Grant it cannot settle that proposal.
    stage = "no-grant self-settlement refusal";
    const own = await museGate05SeedProposal(engine, agent.client, claimScope, {
      subjectRef, predicate: predicateOwn, sentinel: sentinelOwn,
      source: "observed", occurredAt: occurred,
    });
    const ownReview = await engine.client.call("vault.claims.review", {
      claim_ref: own.claimRef,
    } satisfies FacadeInput<"vault.claims.review">);
    expect(ownReview.claim.value).toBe(sentinelOwn);
    const ownOpener = ownReview.opener_ref;
    expect(ownOpener != null && agentRefs.includes(ownOpener)).toBe(true);
    const selfSettleRefusal = await museGate05Refused(() => agent.client.call("vault.claims.settle", {
      claim_ref: own.claimRef, review_id: ownReview.review_id, decision: "approve",
    } satisfies FacadeInput<"vault.claims.settle">));
    const selfSettleRefusalReceipt = await museGate05AwaitClaimReceipt(engine, selfSettleRefusal);
    expect(selfSettleRefusalReceipt.receipt_ref.length).toBeGreaterThan(0);
    expect(museGate05IsPending(await museGate05PendingRefs(engine), own.candidates)).toBe(true);
    expect((await museGate05ListedClaim(engine, subjectRef, predicateOwn, sentinelOwn))?.approval)
      .toBe("proposed");

    // P-GATE-016. The opener cannot mint itself the Grant that would answer
    // its proposal, by either mint door. The registry gains no grant.
    stage = "agent cannot mint answering authority";
    const registryBeforeMints = await museGate05RegistryRefs(engine);
    await museGate05Refused(() => agent.client.call("vault.agents.grants.mint", {
      agent: agent.principalRef, authority_scope: mintScope, verb_classes: [settleClass],
    } satisfies FacadeInput<"vault.agents.grants.mint">));
    await museGate05Refused(() => agent.client.call("vault.consent.create_standing_grant", {
      bound: {
        actor: agent.principalRef,
        class: settleClass,
        envelope: { project: claimScope.scope_project_id, audience: [ownerRef] },
      },
    } satisfies FacadeInput<"vault.consent.create_standing_grant">));
    expect([...await museGate05RegistryRefs(engine)].sort())
      .toEqual([...registryBeforeMints].sort());
    expect(museGate05IsPending(await museGate05PendingRefs(engine), own.candidates)).toBe(true);

    // The owner now mints the agent a real settle Grant. Read it back
    // through the consent registry and the authority audit.
    stage = "owner native claim-review Grant door";
    const minted = await engine.client.call("vault.agents.grants.mint", {
      agent: agent.principalRef, authority_scope: mintScope, verb_classes: [settleClass],
    } satisfies FacadeInput<"vault.agents.grants.mint">);
    const grantRef = minted.grant.grant_ref;
    expect(grantRef.length).toBeGreaterThan(0);
    expect(minted.grant.confers).toBe(true);
    expect((await museGate05RegistryRefs(engine)).has(grantRef)).toBe(true);
    expect((await museGate05AuditRows(engine))
      .some((row) => row.grant_ref === grantRef && row.fold_valid)).toBe(true);

    // Control: with that Grant the agent settles a proposal it did not
    // open. The settlement names the Grant that answered.
    stage = "non-opener control under native claim-review Grant";
    const control = await museGate05SeedProposal(engine, engine.client, claimScope, {
      subjectRef, predicate: predicateControl, sentinel: sentinelControl,
      source: "user_stated", occurredAt: occurred, expectPending: false,
    });
    const controlReview = await engine.client.call("vault.claims.review", {
      claim_ref: control.claimRef,
    } satisfies FacadeInput<"vault.claims.review">);
    const controlOpener = controlReview.opener_ref;
    expect(controlOpener != null && !agentRefs.includes(controlOpener)).toBe(true);
    const controlSettlement = await agent.client.call("vault.claims.settle", {
      claim_ref: control.claimRef, review_id: controlReview.review_id,
      decision: "approve", grant_ref: grantRef,
    } satisfies FacadeInput<"vault.claims.settle">);
    expect(controlSettlement.verdict).toBe("landed");
    expect(controlSettlement.changes[0]?.claim_ref).toBe(control.claimRef);
    expect(controlSettlement.answered_by.kind).toBe("grant");
    if (controlSettlement.answered_by.kind === "grant") {
      expect(controlSettlement.answered_by.grant_ref).toBe(grantRef);
    }
    await engine.awaitReceipt(controlSettlement.receipt_ref);
    expect(museGate05IsPending(await museGate05PendingRefs(engine), control.candidates)).toBe(false);
    expect((await museGate05RequireListedClaim(engine, subjectRef, predicateControl, sentinelControl)).approval)
      .not.toBe("proposed");

    // P-GATE-015, the isolated step. The same Grant, the same review flow,
    // the same actor: settling its OWN proposal still refuses, approve and
    // reject alike, for the first slip and for the second slip alike. Only
    // lineage is left to differ from the control above.
    stage = "granted opener and second-slip self-settlement refusals";
    const grantedSelfSettleRefusal = await museGate05Refused(() => agent.client.call("vault.claims.settle", {
      claim_ref: own.claimRef, review_id: ownReview.review_id,
      decision: "approve", grant_ref: grantRef,
    } satisfies FacadeInput<"vault.claims.settle">));
    await museGate05AwaitClaimReceipt(engine, grantedSelfSettleRefusal);
    await museGate05Refused(() => agentSecondSlip.client.call("vault.claims.settle", {
      claim_ref: own.claimRef, review_id: ownReview.review_id,
      decision: "approve", grant_ref: grantRef,
    } satisfies FacadeInput<"vault.claims.settle">));
    await museGate05Refused(() => agent.client.call("vault.claims.settle", {
      claim_ref: own.claimRef, review_id: ownReview.review_id,
      decision: "reject", grant_ref: grantRef,
    } satisfies FacadeInput<"vault.claims.settle">));
    expect(museGate05IsPending(await museGate05PendingRefs(engine), own.candidates)).toBe(true);
    expect((await museGate05ListedClaim(engine, subjectRef, predicateOwn, sentinelOwn))?.approval)
      .toBe("proposed");

    // Revoke (F3 last step). The owner takes the Grant away; the agent's
    // next settle, even of a proposal outside its lineage, refuses again.
    stage = "native Grant revoke and next-use refusal";
    const revoked = await engine.client.call("vault.agents.grants.revoke", {
      grant_ref: grantRef,
    } satisfies FacadeInput<"vault.agents.grants.revoke">);
    expect(revoked.grant_ref).toBe(grantRef);
    expect(revoked.changed).toBe(true);
    expect((await museGate05RegistryRefs(engine)).has(grantRef)).toBe(false);
    expect((await museGate05AuditRows(engine))
      .some((row) => row.grant_ref === grantRef && row.event_kind === "revoke" && row.fold_valid))
      .toBe(true);
    const afterRevoke = await museGate05SeedProposal(engine, otherProposer.client, claimScope, {
      subjectRef, predicate: predicateAfterRevoke, sentinel: sentinelAfterRevoke,
      source: "user_stated", occurredAt: occurred,
    });
    const afterRevokeReview = await engine.client.call("vault.claims.review", {
      claim_ref: afterRevoke.claimRef,
    } satisfies FacadeInput<"vault.claims.review">);
    await museGate05Refused(() => agent.client.call("vault.claims.settle", {
      claim_ref: afterRevoke.claimRef, review_id: afterRevokeReview.review_id,
      decision: "approve", grant_ref: grantRef,
    } satisfies FacadeInput<"vault.claims.settle">));
    expect(museGate05IsPending(await museGate05PendingRefs(engine), afterRevoke.candidates)).toBe(true);

    // A holder outside the opener's lineage settles both waiting
    // proposals: the opener's own claim is accepted, the other rejected.
    // Each settlement receipt names the person who answered.
    stage = "outside holder settles the two waiting proposals";
    const ownSettlement = await engine.client.call("vault.claims.settle", {
      claim_ref: own.claimRef, review_id: ownReview.review_id, decision: "approve",
    } satisfies FacadeInput<"vault.claims.settle">);
    expect(ownSettlement.verdict).toBe("landed");
    expect(ownSettlement.changes[0]?.claim_ref).toBe(own.claimRef);
    expect(ownSettlement.answered_by.kind).toBe("word");
    if (ownSettlement.answered_by.kind === "word") {
      expect(ownSettlement.answered_by.person_ref.length).toBeGreaterThan(0);
      expect(agentRefs.includes(ownSettlement.answered_by.person_ref)).toBe(false);
    }
    await engine.awaitReceipt(ownSettlement.receipt_ref);
    expect(museGate05IsPending(await museGate05PendingRefs(engine), own.candidates)).toBe(false);
    const rejectedSettlement = await engine.client.call("vault.claims.settle", {
      claim_ref: afterRevoke.claimRef, review_id: afterRevokeReview.review_id, decision: "reject",
    } satisfies FacadeInput<"vault.claims.settle">);
    expect(rejectedSettlement.verdict).toBe("rejected");
    await engine.awaitReceipt(rejectedSettlement.receipt_ref);
    expect(museGate05IsPending(await museGate05PendingRefs(engine), afterRevoke.candidates)).toBe(false);
    const rejectedListed = await museGate05ListedClaim(
      engine, subjectRef, predicateAfterRevoke, sentinelAfterRevoke);
    if (rejectedListed) expect(rejectedListed.approval).toBe("rejected");

    // P-GATE-028. A non-holder's policy change lands as an inert proposal
    // in either direction, and the direct holder door refuses it. Only a
    // holder's change changes effective (trusted) policy, and a holder
    // reverts it in one more change.
    stage = "non-holder policy proposals and owner policy restore";
    const policy0 = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    const default0 = museGate05DefaultView(policy0);
    expect(default0.trusted).toBe(true);
    const manifest0 = default0.manifest;
    const hash0 = default0.body_hash;
    expect(museGate05TrustedHasAuto(policy0, agentRefs)).toBe(false);
    expect(museGate05TrustedHasRule(policy0, narrowRulePrefix)).toBe(false);

    const widenClone = museGate05CloneManifest(manifest0);
    widenClone.actor_ceilings = [...widenClone.actor_ceilings,
      { actor_class: "agent", actor_ref: agent.principalRef, ceiling: "auto" }];
    const widenProposal = await agent.client.call("vault.gate.policy.propose", {
      manifest: widenClone,
    } satisfies FacadeInput<"vault.gate.policy.propose">);
    expect(widenProposal.approval).toBe("proposed");
    expect(widenProposal.manifest.trusted).toBe(false);
    expect((await museGate05ReceiptRefs(engine)).has(widenProposal.receipt_ref)).toBe(true);
    const policyAfterWidenProposal = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(policyAfterWidenProposal.default_manifest_ref).toBe(policy0.default_manifest_ref);
    expect(museGate05DefaultView(policyAfterWidenProposal).body_hash).toBe(hash0);
    expect(museGate05TrustedHasAuto(policyAfterWidenProposal, agentRefs)).toBe(false);

    const narrowClone = museGate05CloneManifest(manifest0);
    narrowClone.rules = [...narrowClone.rules,
      { prefix: narrowRulePrefix, axes: { sensitivity: "restricted" } }];
    const narrowProposal = await agent.client.call("vault.gate.policy.propose", {
      manifest: narrowClone,
    } satisfies FacadeInput<"vault.gate.policy.propose">);
    expect(narrowProposal.approval).toBe("proposed");
    expect(narrowProposal.manifest.trusted).toBe(false);
    expect((await museGate05ReceiptRefs(engine)).has(narrowProposal.receipt_ref)).toBe(true);
    const policyAfterNarrowProposal = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(museGate05DefaultView(policyAfterNarrowProposal).body_hash).toBe(hash0);
    expect(museGate05TrustedHasRule(policyAfterNarrowProposal, narrowRulePrefix)).toBe(false);

    await museGate05Refused(() => agent.client.call("vault.gate.policy.put", {
      manifest_ref: museGate05DefaultView(policyAfterNarrowProposal).manifest_ref,
      expected_body_hash: museGate05DefaultView(policyAfterNarrowProposal).body_hash,
      manifest: widenClone,
    } satisfies FacadeInput<"vault.gate.policy.put">));
    const policyAfterPutRefusal = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(museGate05DefaultView(policyAfterPutRefusal).body_hash).toBe(hash0);
    expect(museGate05TrustedHasAuto(policyAfterPutRefusal, agentRefs)).toBe(false);

    const holderClone = museGate05CloneManifest(manifest0);
    holderClone.rules = [...holderClone.rules,
      { prefix: holderRulePrefix, axes: { criticality: "critical" } }];
    const holderPut = await engine.client.call("vault.gate.policy.put", {
      manifest_ref: museGate05DefaultView(policyAfterPutRefusal).manifest_ref,
      expected_body_hash: museGate05DefaultView(policyAfterPutRefusal).body_hash,
      manifest: holderClone,
    } satisfies FacadeInput<"vault.gate.policy.put">);
    expect(holderPut.approval).toBe("auto");
    expect(holderPut.manifest.trusted).toBe(true);
    expect(holderPut.manifest.body_hash).not.toBe(hash0);
    expect((await museGate05ReceiptRefs(engine)).has(holderPut.receipt_ref)).toBe(true);
    const policyAfterHolderPut = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(museGate05TrustedHasRule(policyAfterHolderPut, holderRulePrefix)).toBe(true);
    expect(museGate05TrustedHasAuto(policyAfterHolderPut, agentRefs)).toBe(false);
    expect(museGate05TrustedHasRule(policyAfterHolderPut, narrowRulePrefix)).toBe(false);

    const revertPut = await engine.client.call("vault.gate.policy.put", {
      manifest_ref: holderPut.manifest.manifest_ref,
      expected_body_hash: holderPut.manifest.body_hash,
      manifest: museGate05CloneManifest(manifest0),
    } satisfies FacadeInput<"vault.gate.policy.put">);
    expect(revertPut.approval).toBe("auto");
    expect((await museGate05ReceiptRefs(engine)).has(revertPut.receipt_ref)).toBe(true);
    const policyAfterRevert = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(museGate05TrustedHasRule(policyAfterRevert, holderRulePrefix)).toBe(false);
    expect(policyAfterRevert.manifests
      .some((row) => row.trusted && row.body_hash === hash0)).toBe(true);

    // Survive a restart. The settled claims, the revoked grant, the
    // refusal receipts and the reverted policy all read back unchanged.
    stage = "settlements revoked Grant and policy survive restart";
    await engine.restart();
    const pendingAfterRestart = await museGate05PendingRefs(engine);
    expect(museGate05IsPending(pendingAfterRestart, own.candidates)).toBe(false);
    expect(museGate05IsPending(pendingAfterRestart, control.candidates)).toBe(false);
    expect(museGate05IsPending(pendingAfterRestart, afterRevoke.candidates)).toBe(false);
    expect((await museGate05RequireListedClaim(engine, subjectRef, predicateOwn, sentinelOwn)).approval)
      .not.toBe("proposed");
    expect((await museGate05RequireListedClaim(engine, subjectRef, predicateControl, sentinelControl)).approval)
      .not.toBe("proposed");
    await engine.awaitReceipt(ownSettlement.receipt_ref);
    await engine.awaitReceipt(controlSettlement.receipt_ref);
    expect((await engine.client.call("vault.receipts.get", {
      receipt_ref: selfSettleRefusalReceipt.receipt_ref,
    }))?.receipt_ref).toBe(selfSettleRefusalReceipt.receipt_ref);
    expect((await museGate05RegistryRefs(engine)).has(grantRef)).toBe(false);
    const policyAfterRestart = await engine.client.call("vault.gate.policy.get",
      {} satisfies FacadeInput<"vault.gate.policy.get">);
    expect(policyAfterRestart.manifests
      .some((row) => row.trusted && row.body_hash === hash0)).toBe(true);
    expect(museGate05TrustedHasAuto(policyAfterRestart, agentRefs)).toBe(false);
    expect(museGate05TrustedHasRule(policyAfterRestart, holderRulePrefix)).toBe(false);
    expect(museGate05TrustedHasRule(policyAfterRestart, narrowRulePrefix)).toBe(false);

    await engine.artifacts.json("muse-gate05-summary.json", {
      ownClaimRef: own.claimRef,
      controlClaimRef: control.claimRef,
      afterRevokeClaimRef: afterRevoke.claimRef,
      grantRef,
      settleClass,
      ownSettlementReceipt: ownSettlement.receipt_ref,
      controlSettlementReceipt: controlSettlement.receipt_ref,
      rejectedSettlementReceipt: rejectedSettlement.receipt_ref,
      selfSettleRefusalReceipt: selfSettleRefusalReceipt.receipt_ref,
      widenProposalReceipt: widenProposal.receipt_ref,
      narrowProposalReceipt: narrowProposal.receipt_ref,
      holderPutReceipt: holderPut.receipt_ref,
      revertPutReceipt: revertPut.receipt_ref,
      originalPolicyBodyHash: hash0,
    });
  } catch (error) {
    const detail = error instanceof PublicHttpError
      ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
      : error instanceof Error ? error.message : String(error);
    if (stage === "non-opener control under native claim-review Grant" && !(error instanceof PublicHttpError)) {
      throw new Error(`MUSE-GATE-05 ${stage}: a local assertion failed before review or settle (job 12 met the owner-seed pending-tray assertion, a TEST BUG: an owner-opened forced-Proposed seed may have Gate Allow and no pending row, record_inner.rs:524-527; the control now passes expectPending: false). Later MISSING DOOR: vault.agents.grants.mint returns a 32-hex federation Grant, not the 64-hex native memory.claim.review Grant; delegate_memory_authoring(ReviewClaim, target) has no facade door. Confirm-only body retained; ${detail}`, { cause: error });
    }
    if (stage === "owner native claim-review Grant door" || stage === "non-opener control under native claim-review Grant") {
      throw new Error(`MUSE-GATE-05 MISSING DOOR 2026-11-11: public vault.agents.grants.mint emits a federation Grant, but vault.claims.settle requires a native memory.claim.review consent Grant (64-hex); delegate_memory_authoring(ReviewClaim, target) has no facade door; ${stage}; ${detail}`, { cause: error });
    }
    throw new Error(`MUSE-GATE-05 ${stage}: ${detail}`, { cause: error });
  } finally {
    await engine.close();
  }
});

// MUSE-GATE-06 — P-GATE-018 / P-GATE-019 (ARCH-0072 #drafter / #drift).
// Doors used, all public: vault.packs.put (install the connector pack),
// vault.packs.connector.prepare (draft the ungranted slate),
// vault.packs.connector.get (second-door read-back of every write),
// vault.packs.connector.grants.get (authority read-back),
// vault.packs.connector.accept (owner stamp / per-row edit / row revoke,
// once over WS so its call receipt can be read back),
// vault.packs.connector.update (manifest drift -> delta slate),
// vault.receipts.get (receipt of the owner's stamp and of the refused
// agent stamp), vault.structural.put + pairActor + self.actor (the wrong
// actor kind: a live agent with core:read/core:write but no owner stamp).
// Unproved here: a live connector.call under an accepted/revoked row and
// qualification release (vault.packs.connector.qualify + grants.put need a
// scripted connector transport and qualification kit that the typed
// surface alone cannot author); elicitation and issuer drift.
// HARNESS NEED: one pinned fixture, id "gate06-connector-pack", carrying
// the exact PACK.md pack-folder bytes (v1 and the version-bumped v2 of the
// same connector pack), the manifest summary and protocol_revision the
// installed transport declares. See MUSE-GATE-06.report.md.

type museGate06Tool = FacadeInput<"vault.packs.connector.prepare">["manifest"]["tools"][number];
type museGate06PackView = FacadeResult<"vault.packs.connector.get">;
type museGate06Grants = FacadeResult<"vault.packs.connector.grants.get">;
type museGate06PackReceipt = NonNullable<FacadeResult<"vault.packs.put">["receipt"]>;

interface museGate06PackFixture {
  protocol_revision: string;
  summary: string;
  v1_files: FacadeInput<"vault.packs.put">["files"];
  v2_files: FacadeInput<"vault.packs.put">["files"];
}

const museGate06Occurred = 1769947200; // Same public setup instant GATE-09 uses.

const museGate06ToolsV1: museGate06Tool[] = [
  {
    name: "read_notes", data_class: "public", header_parameters: [],
    destroys: false, spends: false, sends_outward: false, legacy_ask: false,
    read_only: true, idempotent: true,
  },
  {
    name: "send_note", data_class: "personal", header_parameters: [],
    destroys: false, spends: false, sends_outward: true, legacy_ask: false,
    read_only: false,
  },
  {
    name: "summarize_note", data_class: "public", header_parameters: [],
    destroys: false, spends: false, sends_outward: false, legacy_ask: false,
    read_only: true,
  },
  {
    name: "delete_note", data_class: "personal", header_parameters: [],
    destroys: true, spends: false, sends_outward: false, legacy_ask: false,
    read_only: false,
  },
];

// Drift: read_notes unchanged; send_note narrows its scope enum in the case;
// summarize_note expanded (personal data, sends outward);
// export_notes is new; delete_note is removed.
const museGate06ToolsV2: museGate06Tool[] = [
  {
    name: "read_notes", data_class: "public", header_parameters: [],
    destroys: false, spends: false, sends_outward: false, legacy_ask: false,
    read_only: true, idempotent: true,
  },
  {
    name: "send_note", data_class: "personal", header_parameters: [],
    destroys: false, spends: false, sends_outward: true, legacy_ask: false,
    read_only: false,
  },
  {
    name: "summarize_note", data_class: "personal", header_parameters: [],
    destroys: false, spends: false, sends_outward: true, legacy_ask: false,
    read_only: false,
  },
  {
    name: "export_notes", data_class: "personal", header_parameters: [],
    destroys: false, spends: true, sends_outward: true, legacy_ask: false,
    read_only: false,
  },
];

function museGate06Sorted(values: readonly string[]): string[] {
  return [...values].sort();
}

function museGate06Row(view: museGate06PackView, tool: string): museGate06PackView["rows"][number] {
  const row = view.rows.find((candidate) => candidate.draft.tool === tool);
  if (!row) throw new Error(`Slate row missing for ${tool}`);
  return row;
}

function museGate06GrantRow(
  grants: museGate06Grants,
  tool: string,
): museGate06Grants["authority"]["rows"][number] {
  const row = grants.authority.rows.find((candidate) => candidate.tool === tool);
  if (!row) throw new Error(`Authority row missing for ${tool}`);
  return row;
}

function museGate06ErrorEnvelope(body: unknown): { code: string; message: string } {
  const payload = (body as { error?: unknown } | null)?.error ?? body;
  if (!payload || typeof payload !== "object") throw new Error("Refusal is not the standard error envelope");
  const fields = payload as Record<string, unknown>;
  if (typeof fields.code !== "string" || typeof fields.message !== "string") {
    throw new Error("Refusal envelope lacks a string code and message");
  }
  return { code: fields.code, message: fields.message };
}

function museGate06ReceiptRef(
  frames: readonly { envelope: { receipt_ref?: string | null } }[],
): string {
  const frame = frames.find((candidate) => typeof candidate.envelope.receipt_ref === "string"
    && candidate.envelope.receipt_ref.length > 0);
  if (!frame?.envelope.receipt_ref) throw new Error("WS call left no receipt_ref frame");
  return frame.envelope.receipt_ref;
}

async function museGate06Install(
  engine: EngineFixture,
  files: FacadeInput<"vault.packs.put">["files"],
): Promise<museGate06PackReceipt> {
  const put = await engine.client.call("vault.packs.put", { files });
  expect(put.outcome).not.toBe("blocked");
  if (!put.receipt) throw new Error(`Connector pack install left no receipt: ${put.reason ?? "no reason"}`);
  return put.receipt;
}

suite.test(test, "MUSE-GATE-06", "A connector draft grants nothing until the owner accepts it, and a widened connector asks again while carried rows keep their ruling", async () => {
  const catalog = await loadFixtures();
  const pack = await catalog.readJson<museGate06PackFixture>("gate06-connector-pack");
  let stage = "scripted connector transport setup";
  let primaryFailed = false;
  let primary: unknown;
  const withSchema = (tools: readonly museGate06Tool[], version: "v1" | "v2") => tools.map((tool) => ({
    ...tool,
    resolved_input_schema: {
      type: "object", additionalProperties: false, required: ["scope"],
      properties: { scope: { type: "string",
        enum: tool.name === "send_note" && version === "v2" ? ["personal"] : ["personal", "team"],
      } },
    },
  })).sort((left, right) => left.name.localeCompare(right.name));
  const toolsV1 = withSchema(museGate06ToolsV1, "v1");
  const toolsV2 = withSchema(museGate06ToolsV2, "v2");
  const provider = await ScriptedProviders.start({ id: "muse-gate06-discovery", origins: ["connector"], steps: [] });
  const enqueueDiscovery = (version: string, tools: ReturnType<typeof withSchema>) => {
    provider.enqueue({
      id: `${version}-initialize`, origin: "connector", role: "connector", purpose: `${version} MCP discovery`,
      request: { method: "POST", path: "/mcp", fields: { method: "initialize", params: { protocolVersion: pack.protocol_revision } } },
      response: { kind: "json", body: { jsonrpc: "2.0", id: "initialize", result: {
        protocolVersion: pack.protocol_revision, capabilities: { tools: {} },
        serverInfo: { name: "gate06-notes", version },
      } } },
    });
    provider.enqueue({
      id: `${version}-initialized`, origin: "connector", role: "connector", purpose: `${version} MCP initialized notification`,
      request: { method: "POST", path: "/mcp", fields: { method: "notifications/initialized" } },
      response: { kind: "json", status: 202, body: {} },
    });
    provider.enqueue({
      id: `${version}-tools`, origin: "connector", role: "connector", purpose: `${version} permission declaration`,
      request: { method: "POST", path: "/mcp", fields: { method: "tools/list", params: {} } },
      response: { kind: "json", body: { jsonrpc: "2.0", id: "tools/list:0", result: {
        tools: tools.map((tool) => ({
          name: tool.name, inputSchema: tool.resolved_input_schema,
          annotations: { readOnlyHint: tool.read_only ?? false,
            destructiveHint: tool.destroys, openWorldHint: tool.sends_outward,
            idempotentHint: tool.idempotent ?? false },
        })),
      } } },
    });
  };
  const engine = await EngineFixture.start({ id: "MUSE-GATE-06", profile,
    serverConfig: `[connectors."muse.gate06_notes"]
transport = "mcp_http"
endpoint = "${provider.urls.connector}/mcp"
`,
  });
  try {
    // Install the connector pack through the owner pack door, then draft
    // its admission slate from the typed manifest. The pack source this
    // case stamps is the installed receipt's own source, never invented.
    stage = "install v1 pack source";
    const installedV1 = await museGate06Install(engine, pack.v1_files);
    expect(installedV1.kind).toBe("connector");
    const connector = installedV1.pack_name;
    const sourceV1 = { source_ref: installedV1.source_id, content_hash: installedV1.content_hash };
    stage = "prepare source-bound connector admission from live v1 discovery";
    enqueueDiscovery("v1", toolsV1);
    const prepared = await engine.client.call("vault.packs.connector.prepare", {
      connector,
      source: sourceV1,
      summary: pack.summary,
      protocol_revision: pack.protocol_revision,
      manifest: { pack_source: sourceV1, tools: toolsV1, elicitation: { legacy_ask_tools: [] } },
    } satisfies FacadeInput<"vault.packs.connector.prepare">);

    // P-GATE-018, read back through a different verb: the prepared slate is
    // an unstamped draft. One row per declared tool, drafted at auto, with
    // no owner ruling on any row yet.
    stage = "read ungranted v1 slate";
    const drafted = await awaitPublic(
      () => engine.client.call("vault.packs.connector.get", { connector }),
      (view) => view.rows.length === toolsV1.length + 1,
      { label: "drafted connector slate rows", timeoutMs: LIMITS.requestMs },
    );
    expect(drafted.basis.connector).toBe(connector);
    expect(drafted.basis.source).toEqual(sourceV1);
    expect(prepared.basis.connector).toBe(connector);
    expect(drafted.stamped).toBe(false);
    expect(drafted.consent_required).toBe(true);
    expect(drafted.status).toBe("pending");
    expect(museGate06Sorted(drafted.rows.map((row) => row.draft.tool)))
      .toEqual(museGate06Sorted([...toolsV1.map((tool) => tool.name), "@elicitation"]));
    for (const row of drafted.rows) {
      expect(row.owner_override ?? null).toBeNull();
    }
    // The draft grants nothing: per-capability authority for this reviewed
    // source is not ready and carries no minted grant on any row.
    stage = "read unstamped connector authority";
    const draftGrants = await engine.client.call("vault.packs.connector.grants.get", {
      basis: drafted.basis,
    } satisfies FacadeInput<"vault.packs.connector.grants.get">);
    expect(draftGrants.authority.connector).toBe(connector);
    expect(draftGrants.authority.ready).toBe(false);
    expect(draftGrants.authority.rows.every((row) => row.grant_id == null)).toBe(true);
    await engine.artifacts.json("gate06-draft.json", { drafted, draftGrants });

    // The wrong actor kind: a live paired agent with core read/write scope
    // is not the owner and cannot stamp its own widening of the slate.
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Gate06 Slate Agent" }, occurred_at: museGate06Occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agentSelf = await agent.client.call("self.actor", {});
    expect(agentSelf.actor_class).toBe("agent");
    stage = "agent cannot stamp v1 slate";
    const agentStamp = await agent.client.raw("POST", "/v1/core/facade/vault.packs.connector.accept", {
      basis: drafted.basis,
      rows: {
        read_notes: "always_allow", send_note: "always_allow",
        summarize_note: "always_allow", delete_note: "always_allow",
      },
    } satisfies FacadeInput<"vault.packs.connector.accept">);
    expect([401, 403].includes(agentStamp.status)).toBe(true);
    const agentRefusal = museGate06ErrorEnvelope(agentStamp.body);
    expect(agentRefusal.code.length).toBeGreaterThan(0);
    expect(agentRefusal.message.length).toBeGreaterThan(0);
    const afterAgentStamp = await engine.client.call("vault.packs.connector.get", { connector });
    expect(afterAgentStamp.stamped).toBe(false);
    expect(afterAgentStamp.rows.every((row) => row.owner_override == null)).toBe(true);
    await engine.artifacts.json("gate06-agent-stamp-refused.json", {
      status: agentStamp.status, code: agentRefusal.code,
    });

    // The owner accepts with per-row edits, over WS, so the stamp's call
    // receipt can be read back through vault.receipts.get.
    const ownerEdits = {
      read_notes: "always_allow", send_note: "always_ask",
      summarize_note: "auto", delete_note: "never_allow",
    } as const;
    stage = "owner stamps v1 slate over websocket";
    const ownerSocket = await engine.websocket();
    let stampReceiptRef = "";
    try {
      const stampedCall = await ownerSocket.call("vault.packs.connector.accept", {
        basis: afterAgentStamp.basis, rows: { ...ownerEdits },
      } satisfies FacadeInput<"vault.packs.connector.accept">);
      stampReceiptRef = museGate06ReceiptRef(stampedCall.frames);
    } finally { ownerSocket.close() }
    stage = "read owner stamp call receipt";
    const stampReceipt = await engine.client.call("vault.receipts.get", { receipt_ref: stampReceiptRef });
    if (!stampReceipt) throw new Error("Owner slate stamp left no readable call receipt");
    expect(stampReceipt.verb).toBe("vault.packs.connector.accept");
    expect(stampReceipt.outcome).toBe("ok");

    // Read the stamp back through get and through grants.get. Accepting
    // does not qualify the connector: the key stays pending until the
    // qualification probes pass, which this case does not run.
    stage = "read owner stamp and authority settings";
    const stamped = await engine.client.call("vault.packs.connector.get", { connector });
    expect(stamped.stamped).toBe(true);
    expect(museGate06Row(stamped, "read_notes").owner_override?.disposition).toBe("always_allow");
    expect(museGate06Row(stamped, "send_note").owner_override?.disposition).toBe("always_ask");
    expect(museGate06Row(stamped, "delete_note").owner_override?.disposition).toBe("never_allow");
    stage = "read stamped connector authority";
    const stampedGrants = await engine.client.call("vault.packs.connector.grants.get", {
      basis: stamped.basis,
    } satisfies FacadeInput<"vault.packs.connector.grants.get">);
    expect(museGate06GrantRow(stampedGrants, "read_notes").setting).toBe("always_allow");
    expect(museGate06GrantRow(stampedGrants, "send_note").setting).toBe("always_ask");
    expect(museGate06GrantRow(stampedGrants, "summarize_note").setting).toBe("auto");
    expect(museGate06GrantRow(stampedGrants, "delete_note").setting).toBe("never_allow");
    await engine.artifacts.json("gate06-stamped.json", { stamped, stampedGrants });

    // P-GATE-019: the pack moves to its version-bumped v2 source and the
    // manifest drifts. Only the expansions re-ask; the unchanged and the
    // narrowed rows carry forward; the removed tool drops without an ask.
    // send_note narrows the same scope enum, a restriction the engine can prove.
    stage = "install v2 pack source";
    const installedV2 = await museGate06Install(engine, pack.v2_files);
    expect(installedV2.pack_name).toBe(connector);
    expect(installedV2.content_hash).not.toBe(installedV1.content_hash);
    const sourceV2 = { source_ref: installedV2.source_id, content_hash: installedV2.content_hash };
    stage = "update connector admission from live v2 discovery";
    enqueueDiscovery("v2", toolsV2);
    const delta = await engine.client.call("vault.packs.connector.update", {
      prior: stamped.basis,
      source: sourceV2,
      protocol_revision: pack.protocol_revision,
      manifest: { pack_source: sourceV2, tools: toolsV2, elicitation: { legacy_ask_tools: [] } },
    } satisfies FacadeInput<"vault.packs.connector.update">);
    expect(delta.changed).toBe(true);
    expect(delta.current.basis.connector).toBe(connector);
    expect(museGate06Sorted(delta.reask)).toEqual(["export_notes", "summarize_note"]);
    expect(museGate06Sorted(delta.carried)).toEqual(["@elicitation", "read_notes", "send_note"]);
    expect(museGate06Sorted(delta.dropped)).toEqual(["delete_note"]);
    await engine.artifacts.json("gate06-delta.json", delta);

    // Drift is durable state on the key, not a transient prompt: restart,
    // then read the delta slate back. Carried rows keep the owner's v1
    // ruling; re-asked rows carry no ruling and no minted grant.
    stage = "restart and read carried and reasked rows";
    await engine.restart();
    const drifted = await awaitPublic(
      () => engine.client.call("vault.packs.connector.get", { connector }),
      (view) => view.rows.some((row) => row.draft.tool === "export_notes"),
      { label: "drifted connector slate after restart", timeoutMs: LIMITS.requestMs },
    );
    expect(drifted.basis.source).toEqual(sourceV2);
    expect(museGate06Sorted(drifted.rows.map((row) => row.draft.tool)))
      .toEqual(museGate06Sorted([...toolsV2.map((tool) => tool.name), "@elicitation"]));
    expect(museGate06Row(drifted, "read_notes").owner_override?.disposition).toBe("always_allow");
    expect(museGate06Row(drifted, "send_note").owner_override?.disposition).toBe("always_ask");
    expect(museGate06Row(drifted, "summarize_note").owner_override ?? null).toBeNull();
    expect(museGate06Row(drifted, "export_notes").owner_override ?? null).toBeNull();
    stage = "read drifted connector authority";
    const driftGrants = await engine.client.call("vault.packs.connector.grants.get", {
      basis: drifted.basis,
    } satisfies FacadeInput<"vault.packs.connector.grants.get">);
    expect(museGate06GrantRow(driftGrants, "read_notes").setting).toBe("always_allow");
    expect(museGate06GrantRow(driftGrants, "send_note").setting).toBe("always_ask");
    expect(driftGrants.authority.rows
      .filter((row) => row.tool === "summarize_note" || row.tool === "export_notes")
      .every((row) => row.grant_id == null)).toBe(true);

    // The agent is still a live agent after the restart, and still cannot
    // stamp the expansion for itself. The refusal leaves a call receipt
    // the owner can read back.
    const agentSelfAfterRestart = await agent.client.call("self.actor", {});
    expect(agentSelfAfterRestart.actor_class).toBe("agent");
    stage = "agent delta-stamp HTTP refusal and receipt readback";
    let agentRefusalReceiptRef = "";
    try {
      await agent.client.call("vault.packs.connector.accept", {
        basis: drifted.basis,
        rows: { summarize_note: "always_allow", export_notes: "always_allow" },
      } satisfies FacadeInput<"vault.packs.connector.accept">);
      throw new Error("Agent delta stamp was not refused");
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      expect([401, 403]).toContain(error.reply.status);
      const receiptRef = error.error?.receiptRef;
      if (typeof receiptRef !== "string" || receiptRef.length === 0) {
        throw new Error(`MUSE-GATE-06 ${stage}: refusal has no receiptRef; status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error });
      }
      agentRefusalReceiptRef = receiptRef;
    }
    stage = "read agent delta-stamp refusal call receipt";
    const refusalReceipt = await engine.client.call("vault.receipts.get", {
      receipt_ref: agentRefusalReceiptRef,
    });
    if (!refusalReceipt) throw new Error("Refused agent delta stamp left no readable call receipt");
    expect(refusalReceipt.verb).toBe("vault.packs.connector.accept");
    if (refusalReceipt.outcome === "ok") throw new Error("Refused agent delta stamp receipt reads ok");
    expect(refusalReceipt.outcome.refused.code.length).toBeGreaterThan(0);
    const afterAgentDelta = await engine.client.call("vault.packs.connector.get", { connector });
    expect(museGate06Row(afterAgentDelta, "summarize_note").owner_override ?? null).toBeNull();
    expect(museGate06Row(afterAgentDelta, "export_notes").owner_override ?? null).toBeNull();
    expect(museGate06Row(afterAgentDelta, "read_notes").owner_override?.disposition).toBe("always_allow");

    // Only the re-asked rows need the owner's tap. Stamping just those
    // changed rows lands the delta; carried rows keep their v1 ruling.
    stage = "owner stamps only reasked rows";
    await engine.client.call("vault.packs.connector.accept", {
      basis: afterAgentDelta.basis,
      rows: { summarize_note: "always_ask", export_notes: "never_allow" },
    } satisfies FacadeInput<"vault.packs.connector.accept">);
    const restamped = await engine.client.call("vault.packs.connector.get", { connector });
    expect(restamped.stamped).toBe(true);
    expect(museGate06Row(restamped, "summarize_note").owner_override?.disposition).toBe("always_ask");
    expect(museGate06Row(restamped, "export_notes").owner_override?.disposition).toBe("never_allow");
    expect(museGate06Row(restamped, "read_notes").owner_override?.disposition).toBe("always_allow");
    expect(museGate06Row(restamped, "send_note").owner_override?.disposition).toBe("always_ask");
    stage = "read delta-restamped connector authority";
    const restampedGrants = await engine.client.call("vault.packs.connector.grants.get", {
      basis: restamped.basis,
    } satisfies FacadeInput<"vault.packs.connector.grants.get">);
    expect(museGate06GrantRow(restampedGrants, "summarize_note").setting).toBe("always_ask");
    expect(museGate06GrantRow(restampedGrants, "export_notes").setting).toBe("never_allow");
    expect(museGate06GrantRow(restampedGrants, "read_notes").setting).toBe("always_allow");
    expect(museGate06GrantRow(restampedGrants, "send_note").setting).toBe("always_ask");

    // Revoke one previously allowed row at the same door. Never allow
    // removes that row's authority and leaves every other row standing.
    stage = "owner revokes one allowed row";
    await engine.client.call("vault.packs.connector.accept", {
      basis: restamped.basis,
      rows: { read_notes: "never_allow" },
    } satisfies FacadeInput<"vault.packs.connector.accept">);
    const revoked = await engine.client.call("vault.packs.connector.get", { connector });
    expect(museGate06Row(revoked, "read_notes").owner_override?.disposition).toBe("never_allow");
    expect(museGate06Row(revoked, "send_note").owner_override?.disposition).toBe("always_ask");
    stage = "read revoked connector authority";
    const revokedGrants = await engine.client.call("vault.packs.connector.grants.get", {
      basis: revoked.basis,
    } satisfies FacadeInput<"vault.packs.connector.grants.get">);
    expect(museGate06GrantRow(revokedGrants, "read_notes").setting).toBe("never_allow");
    expect(museGate06GrantRow(revokedGrants, "send_note").setting).toBe("always_ask");
    await engine.artifacts.json("gate06-final.json", { revoked, revokedGrants });
  } catch (error) {
    primaryFailed = true;
    primary = error instanceof PublicHttpError ? new Error(
      `MUSE-GATE-06 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    ) : new Error(`MUSE-GATE-06 ${stage}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  } finally {
    const cleanup = await Promise.allSettled([engine.close(), provider.close()]);
    const failures = cleanup.filter((row): row is PromiseRejectedResult => row.status === "rejected").map((row) => row.reason);
    if (failures.length > 0) throw new AggregateError(primaryFailed ? [primary, ...failures] : failures,
      `${primaryFailed ? String(primary) : "MUSE-GATE-06 cleanup"}; cleanup: ${failures.map(String).join("; ")}`);
    if (primaryFailed) throw primary;
  }
});

// MUSE-GATE-07 — guest-grant encoding plus scoped-export ceiling/request,
// a PARTIAL case for two promises:
//
// P-GATE-020: a guest Grant permits read or propose but not authority widening.
//   Proved here at the owner mint door: a Connect guest grant carrying the
//   string verb "widen" is refused, a non-owner agent cannot mint the valid
//   grant, and the valid read/propose grant resolves to exactly those verbs
//   over a named world, never base. The grant is read back, survives a
//   restart, and is then revoked.
// P-GATE-022: an empty ceiling grants no access, while an empty request adds
//   no narrowing.
//   Proved here at vault.export.scoped: an empty selector exports both seeded
//   claims under an all-axis channel ceiling, while an empty ({}) channel
//   ceiling and an explicit bottom channel ceiling each export no records,
//   even though the caller credential ceiling is unchanged.
//
// Doors used: vault.federation.connect.identity,
// vault.federation.connect.grants.mint, vault.guests.revoke,
// vault.authority.audit, vault.receipts.get, vault.scope.ceiling,
// vault.scope.position, vault.export.scoped, vault.claims.upsert,
// vault.claims.list, vault.get, vault.structural.put,
// vault.conversations.create, vault.witness and vault.people.create.
//
// What stays unproved: a live guest acting through guest tools/call
// (vault.guests.export_envelope / vault.guests.propose under its own
// grant-bound credential from vault.guests.mint_slip), reciprocal pact
// activation, and a guest losing its grant mid-flow. The harness has no
// guest-actor client for a minted guest slip, and this one-slot file cannot
// run the two live peer vaults an active pact needs. See the report.

type museGate07Axis<T> =
  | { kind: "bottom" }
  | { kind: "all" }
  | { kind: "some"; values: T[] };
type museGate07Scope = FacadeInput<"vault.federation.connect.grants.mint">["authority_scope"];
type museGate07AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museGate07Claim = FacadeResult<"vault.claims.list">["value"][number];
type museGate07Selector = FacadeInput<"vault.export.scoped">["selector"];
type museGate07ChannelCeiling = FacadeInput<"vault.export.scoped">["channel"]["scope"];
type museGate07ExportRecord = FacadeResult<"vault.export.scoped">["records"][number];
interface museGate07ErrorEnvelope {
  code: string;
  message: string;
  requestId: string;
  receiptRef: string | undefined;
}

const museGate07MintVerb = "vault.federation.connect.grants.mint";

function museGate07AxisGrants<T>(axis: museGate07Axis<T> | undefined, value: T): boolean {
  if (!axis || axis.kind === "bottom") return false;
  if (axis.kind === "all") return true;
  return axis.values.includes(value);
}

function museGate07VerbSet(axis: museGate07Axis<string> | undefined): string[] {
  return axis?.kind === "some" ? [...axis.values].sort() : [];
}

function museGate07IsRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function museGate07ParseError(body: unknown): museGate07ErrorEnvelope {
  if (!museGate07IsRecord(body) || !museGate07IsRecord(body.error)) {
    throw new Error("Refusal body is not the standard {error:{...}} envelope");
  }
  const error = body.error;
  if (typeof error.code !== "string" || error.code.length === 0) {
    throw new Error("Refusal envelope has no error.code");
  }
  if (typeof error.message !== "string" || error.message.length === 0) {
    throw new Error("Refusal envelope has no error.message");
  }
  if (typeof error.requestId !== "string" || error.requestId.length === 0) {
    throw new Error("Refusal envelope has no error.requestId");
  }
  return {
    code: error.code,
    message: error.message,
    requestId: error.requestId,
    receiptRef: typeof error.receiptRef === "string" ? error.receiptRef : undefined,
  };
}

async function museGate07AuditRows(client: PublicHttpClient): Promise<museGate07AuditRow[]> {
  const rows: museGate07AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500,
      ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

async function museGate07ExpectRefusedMint(
  engine: EngineFixture,
  reply: { status: number; body: unknown },
  actorRef: string,
): Promise<void> {
  expect(reply.status).toBeGreaterThanOrEqual(400);
  expect(reply.status).toBeLessThan(500);
  const envelope = museGate07ParseError(reply.body);
  if (!envelope.receiptRef) {
    throw new Error("Refused guest-grant mint left no error.receiptRef to read back");
  }
  const receiptRef = envelope.receiptRef;
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", {
      receipt_ref: receiptRef,
    } satisfies FacadeInput<"vault.receipts.get">),
    (value) => value !== null,
    { label: `MUSE-GATE-07 refused guest-grant mint call receipt ${receiptRef}`, timeoutMs: LIMITS.requestMs },
  );
  if (!receipt) throw new Error("Refused guest-grant mint call receipt reads as none");
  expect(receipt.receipt_ref).toBe(receiptRef);
  expect(receipt.verb).toBe(museGate07MintVerb);
  expect(receipt.actor_ref).toBe(actorRef);
  if (receipt.outcome === "ok") {
    throw new Error("Refused guest-grant mint receipt does not record a refusal");
  }
  expect(receipt.outcome.refused.code).toBe(envelope.code);
}

function museGate07FindExportRecord(
  records: readonly museGate07ExportRecord[],
  claim: museGate07Claim,
): museGate07ExportRecord | undefined {
  const wanted = new Set(
    [claim.claim_ref, claim.short_ref ?? "", claim.claim?.id ?? "", claim.claim?.short_id ?? ""]
      .filter((value) => value.length > 0),
  );
  return records.find((row) =>
    wanted.has(row.record.id) || wanted.has(row.record.short_id ?? ""));
}

function museGate07RecordIds(records: readonly museGate07ExportRecord[]): string[] {
  return records.map((row) => row.record.id).sort();
}

async function museGate07Export(
  client: PublicHttpClient,
  selector: museGate07Selector,
  channelRef: string,
  scope: museGate07ChannelCeiling,
): Promise<FacadeResult<"vault.export.scoped">> {
  return client.call("vault.export.scoped", {
    selector,
    channel: { channel_ref: channelRef, scope },
  } satisfies FacadeInput<"vault.export.scoped">);
}

async function museGate07ReadClaim(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
  expectedValue: string,
): Promise<museGate07Claim> {
  const list = await client.call("vault.claims.list", {
    subject_ref: subjectRef, predicate, limit: 1000,
  } satisfies FacadeInput<"vault.claims.list">);
  expect(list.narrowing.applied.deny_all).toBe(false);
  expect(list.value).toHaveLength(1);
  const claim = list.value[0]!;
  expect(claim.subject_ref).toBe(subjectRef);
  expect(claim.predicate).toBe(predicate);
  expect(claim.value).toBe(expectedValue);
  return claim;
}

suite.test(test, "MUSE-GATE-07", "A guest grant encodes only read and propose, and an empty ceiling exports nothing while an empty selector narrows nothing", async () => {
  let stage = "peer identity setup";
  const occurred = 1769947200; // Public setup input, as in GATE-09.
  const suffix = secretHex(8);
  const personName = `Gate Seven Person ${suffix}`;
  const agentName = `Gate Seven Agent ${suffix}`;
  const worldName = `Gate Seven Story World ${suffix}`;
  const baseValue = `muse-gate-07-base-${suffix}`;
  const worldValue = `muse-gate-07-world-${suffix}`;
  const channelRef = `muse-gate-07-channel-${suffix}`;
  redactor.add(suffix, personName, agentName, worldName, baseValue, worldValue, channelRef);
  const basePredicate = "decision.practical";
  const worldPredicate = "storytelling.genre";

  // A real peer vault identity, read through its public door and then closed:
  // this one-slot file never runs two vaults at once (SECRETS-01 pattern).
  const peer = await EngineFixture.start({ id: "MUSE-GATE-07-peer", profile });
  let peerIdentity: FacadeResult<"vault.federation.connect.identity">;
  try {
    peerIdentity = await peer.client.call("vault.federation.connect.identity", {
    } satisfies FacadeInput<"vault.federation.connect.identity">);
    expect(peerIdentity.vault.length).toBeGreaterThan(0);
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-GATE-07 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw error;
  } finally { await peer.close() }

  const engine = await EngineFixture.start({ id: "MUSE-GATE-07", profile });
  let primaryFailed = false;
  let primary: unknown;
  try {
    stage = "primary vault claim and actor setup";
    const ownerHex = engine.pairedActor.principalRef;
    const ceilingBefore = await engine.client.call("vault.scope.ceiling", {
    } satisfies FacadeInput<"vault.scope.ceiling">);
    expect(ceilingBefore.kind).toBe("ceiling");

    const worldRecord = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: worldName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const worldView = await engine.client.call("vault.get", {
      entity_ref: worldRecord.entity_ref,
    } satisfies FacadeInput<"vault.get">);
    if (!worldView.value) throw new Error("Named WORLD is not readable through vault.get");
    expect(worldView.value.kind).toBe("WORLD");
    expect(worldView.value.id_hex).toBe(worldRecord.id_hex);
    const worldId = worldRecord.id_hex;

    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witness = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: occurred,
      messages: [{
        author: "user", message_type: "text",
        content: `This distinct person is ${personName}.`,
        is_visible: true, order: 0,
      }],
    } satisfies FacadeInput<"vault.witness">);
    const turn = await engine.client.call("vault.get", {
      entity_ref: witness.turn_short_id,
    } satisfies FacadeInput<"vault.get">);
    if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
      throw new Error("Witnessed TURN is missing");
    }
    const createdPerson = await engine.client.call("vault.people.create", {
      identity: { name: personName },
      identity_evidence_refs: [turn.value.id_hex],
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.people.create">);
    const personId = createdPerson.person.id_hex;
    expect(personId).not.toBe(ownerHex);
    const personView = await engine.client.call("vault.get", {
      entity_ref: createdPerson.person.entity_ref,
    } satisfies FacadeInput<"vault.get">);
    expect(personView.value?.kind).toBe("PERSON");

    const baseScope = await ownerBaseClaimScope(engine.client, ownerHex);
    const worldScope: FacadeInput<"vault.claims.upsert">["scope"] = {
      ...baseScope, world_id: worldId,
    };
    const baseClaimWrite = await engine.client.call("vault.claims.upsert", {
      predicate: basePredicate, subject_ref: personId, value: baseValue,
      confidence: 1, source: "user_stated", scope: baseScope, occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(baseClaimWrite.receipt_ref);
    const worldClaimWrite = await engine.client.call("vault.claims.upsert", {
      predicate: worldPredicate, subject_ref: personId, value: worldValue,
      confidence: 1, source: "user_stated", scope: worldScope, occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(worldClaimWrite.receipt_ref);

    const baseClaim = await museGate07ReadClaim(engine.client, personId, basePredicate, baseValue);
    expect(baseClaim.claim_scope.world_id).toBe(baseScope.world_id);
    const worldClaim = await museGate07ReadClaim(engine.client, personId, worldPredicate, worldValue);
    expect(worldClaim.claim_scope.world_id).toBe(worldId);
    const worldSelectorRef = worldClaim.world_ref ?? worldId;
    expect(worldSelectorRef.length).toBeGreaterThan(0);

    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: agentName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });

    const facetId = baseScope.scope_facet_id;
    const validScope: museGate07Scope = {
      worlds: { kind: "some", values: [worldId] },
      facets: { kind: "some", values: [facetId] },
      verbs: { kind: "some", values: ["read", "propose"] },
      bands: { kind: "all" }, audience: { kind: "all" },
      sensitivity: { kind: "at_most", value: "private" },
    };
    const widenScope: museGate07Scope = {
      worlds: { kind: "some", values: [worldId] },
      facets: { kind: "some", values: [facetId] },
      verbs: { kind: "some", values: ["read", "widen"] },
      bands: { kind: "all" }, audience: { kind: "all" },
      sensitivity: { kind: "at_most", value: "private" },
    };
    const validMint = {
      peer_vault: peerIdentity.vault, authority_scope: validScope,
    } satisfies FacadeInput<"vault.federation.connect.grants.mint">;

    const auditBefore = await museGate07AuditRows(engine.client);
    const auditBeforeHashes = new Set(auditBefore.map((row) => row.entry_hash));

    // No grant yet: a scope value outside read/propose is rejected, and the
    // refusal reads back as a refused call receipt naming the owner actor.
    stage = "mint rejects widening verb";
    const widenAttempt = await engine.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.federation.connect.grants.mint", {
        peer_vault: peerIdentity.vault, authority_scope: widenScope,
      } satisfies FacadeInput<"vault.federation.connect.grants.mint">);
    await museGate07ExpectRefusedMint(engine, widenAttempt, ownerHex);

    // Wrong actor kind: a paired core:read/core:write agent is not the owner
    // and cannot mint the valid grant either.
    stage = "non-owner mint refusal";
    const agentAttempt = await agent.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.federation.connect.grants.mint", validMint);
    await museGate07ExpectRefusedMint(engine, agentAttempt, agent.principalRef);

    const auditAfterRefusals = await museGate07AuditRows(engine.client);
    const refusedGrants = auditAfterRefusals.filter((row) =>
      !auditBeforeHashes.has(row.entry_hash)
      && row.event_kind === "grant"
      && row.peer_vault_ref === peerIdentity.vault);
    expect(refusedGrants).toHaveLength(0);

    // Grant, allowed: read/propose over the named world, never base.
    stage = "owner valid six-axis guest-grant mint";
    const minted = await engine.client.call("vault.federation.connect.grants.mint", validMint);
    expect(minted.grant.length).toBeGreaterThan(0);
    expect(minted.guest_actor.length).toBeGreaterThan(0);
    expect(minted.guest_actor).not.toBe(ownerHex);
    expect(museGate07VerbSet(minted.resolved_scope.verbs)).toEqual(["propose", "read"]);
    expect(museGate07AxisGrants(minted.resolved_scope.worlds, worldId)).toBe(true);
    expect(museGate07AxisGrants(minted.resolved_scope.worlds, baseScope.world_id)).toBe(false);
    expect(museGate07AxisGrants(minted.resolved_scope.facets, facetId)).toBe(true);
    stage = "read guest grant and guest actor through vault.get";
    const grantView = await engine.client.call("vault.get", {
      entity_ref: minted.grant,
    } satisfies FacadeInput<"vault.get">);
    if (!grantView.value) throw new Error("Minted guest grant is not readable through vault.get");
    expect(grantView.value.id_hex === minted.grant || grantView.value.short_ref === minted.grant).toBe(true);
    const guestActorView = await engine.client.call("vault.get", {
      entity_ref: minted.guest_actor,
    } satisfies FacadeInput<"vault.get">);
    if (!guestActorView.value) throw new Error("Guest actor is not readable through vault.get");

    // A grant naming base must never resolve to a grant over base.
    stage = "mint rejects base world";
    const baseAttempt = await engine.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.federation.connect.grants.mint", {
        peer_vault: peerIdentity.vault,
        authority_scope: {
          worlds: { kind: "some", values: [baseScope.world_id] },
          facets: { kind: "some", values: [facetId] },
          verbs: { kind: "some", values: ["read"] },
          bands: { kind: "all" }, audience: { kind: "all" },
          sensitivity: { kind: "at_most", value: "private" },
        },
      } satisfies FacadeInput<"vault.federation.connect.grants.mint">);
    if (baseAttempt.status >= 200 && baseAttempt.status < 300) {
      const mintedBase = baseAttempt.body as FacadeResult<"vault.federation.connect.grants.mint">;
      expect(museGate07AxisGrants(mintedBase.resolved_scope.worlds, baseScope.world_id)).toBe(false);
      const revokedBase = await engine.client.call("vault.guests.revoke", {
        grant_ref: mintedBase.grant,
      } satisfies FacadeInput<"vault.guests.revoke">);
      expect(revokedBase.changed).toBe(true);
    } else {
      await museGate07ExpectRefusedMint(engine, baseAttempt, ownerHex);
    }

    // An empty guest-grant ceiling must never resolve to access.
    stage = "intentionally empty guest ceiling";
    const emptyGrantAttempt = await engine.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.federation.connect.grants.mint", {
        peer_vault: peerIdentity.vault, authority_scope: {},
      } satisfies FacadeInput<"vault.federation.connect.grants.mint">);
    if (emptyGrantAttempt.status >= 200 && emptyGrantAttempt.status < 300) {
      const mintedEmpty = emptyGrantAttempt.body as FacadeResult<"vault.federation.connect.grants.mint">;
      expect(museGate07AxisGrants(mintedEmpty.resolved_scope.worlds, worldId)).toBe(false);
      expect(museGate07AxisGrants(mintedEmpty.resolved_scope.worlds, baseScope.world_id)).toBe(false);
      expect(museGate07AxisGrants(mintedEmpty.resolved_scope.facets, facetId)).toBe(false);
      const revokedEmpty = await engine.client.call("vault.guests.revoke", {
        grant_ref: mintedEmpty.grant,
      } satisfies FacadeInput<"vault.guests.revoke">);
      expect(revokedEmpty.changed).toBe(true);
    } else {
      await museGate07ExpectRefusedMint(engine, emptyGrantAttempt, ownerHex);
    }

    const allCeiling: museGate07ChannelCeiling = {
      worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
      audience: { kind: "all" }, verbs: { kind: "all" }, sensitivity: { kind: "all" },
    };
    const bottomCeiling: museGate07ChannelCeiling = {
      worlds: { kind: "bottom" }, facets: { kind: "bottom" }, bands: { kind: "bottom" },
      audience: { kind: "bottom" }, verbs: { kind: "bottom" },
      sensitivity: { kind: "bottom" },
    };
    const emptyCeiling: museGate07ChannelCeiling = {};

    // An empty request narrows nothing: both seeded claims export.
    stage = "empty-selector all-ceiling export";
    const emptyRequestExport = await museGate07Export(engine.client, {}, channelRef, allCeiling);
    expect(emptyRequestExport.credential).toEqual(ceilingBefore);
    const baseExportRow = museGate07FindExportRecord(emptyRequestExport.records, baseClaim);
    if (!baseExportRow) throw new Error("Empty-selector export omitted the base claim");
    const worldExportRow = museGate07FindExportRecord(emptyRequestExport.records, worldClaim);
    if (!worldExportRow) throw new Error("Empty-selector export omitted the named-world claim");

    stage = "empty-world-selector export";
    const emptyWorldsExport = await museGate07Export(engine.client, {
      worlds: { kind: "worlds", world_refs: [], include_base: false },
    }, channelRef, allCeiling);
    expect(museGate07RecordIds(emptyWorldsExport.records))
      .toEqual(museGate07RecordIds(emptyRequestExport.records));

    // A named request does narrow: the named world alone, without base.
    stage = "named-world-selector export";
    const namedWorldExport = await museGate07Export(engine.client, {
      worlds: { kind: "world", world_ref: worldSelectorRef, include_base: false },
    }, channelRef, allCeiling);
    expect(museGate07FindExportRecord(namedWorldExport.records, worldClaim)).toBeDefined();
    expect(museGate07FindExportRecord(namedWorldExport.records, baseClaim)).toBeUndefined();

    // Empty and bottom ceilings grant nothing, through the same empty request.
    stage = "empty channel-ceiling export";
    const emptyCeilingExport = await museGate07Export(engine.client, {}, channelRef, emptyCeiling);
    expect(emptyCeilingExport.records).toHaveLength(0);
    expect(emptyCeilingExport.credential).toEqual(ceilingBefore);
    expect(museGate07AxisGrants(emptyCeilingExport.applied.worlds, worldId)).toBe(false);
    expect(museGate07AxisGrants(emptyCeilingExport.applied.worlds, baseScope.world_id)).toBe(false);
    stage = "bottom channel-ceiling export";
    const bottomCeilingExport = await museGate07Export(engine.client, {}, channelRef, bottomCeiling);
    expect(bottomCeilingExport.records).toHaveLength(0);
    expect(bottomCeilingExport.credential).toEqual(ceilingBefore);

    // The empty exports removed nothing: the ordinary read door still reads both.
    await museGate07ReadClaim(engine.client, personId, basePredicate, baseValue);
    await museGate07ReadClaim(engine.client, personId, worldPredicate, worldValue);
    stage = "read exported record position";
    const position = await engine.client.call("vault.scope.position", {
      record_ref: worldExportRow.record.id,
    } satisfies FacadeInput<"vault.scope.position">);
    if (!position.value) throw new Error("Named-world claim has no readable record position");
    expect(position.narrowing.applied.deny_all).toBe(false);

    await engine.artifacts.json("muse-gate-07-summary.json", {
      peer_vault: peerIdentity.vault,
      world_id: worldId,
      grant: minted.grant,
      guest_actor: minted.guest_actor,
      resolved_scope: minted.resolved_scope,
      exported_records: museGate07RecordIds(emptyRequestExport.records),
      named_world_records: museGate07RecordIds(namedWorldExport.records),
    });

    stage = "restart durable grant claim and ceiling reads";
    await engine.restart();

    const ceilingAfter = await engine.client.call("vault.scope.ceiling", {
    } satisfies FacadeInput<"vault.scope.ceiling">);
    expect(ceilingAfter).toEqual(ceilingBefore);
    const baseClaimAfter = await museGate07ReadClaim(engine.client, personId, basePredicate, baseValue);
    const worldClaimAfter = await museGate07ReadClaim(engine.client, personId, worldPredicate, worldValue);
    const emptyRequestAfter = await museGate07Export(engine.client, {}, channelRef, allCeiling);
    expect(museGate07FindExportRecord(emptyRequestAfter.records, baseClaimAfter)).toBeDefined();
    expect(museGate07FindExportRecord(emptyRequestAfter.records, worldClaimAfter)).toBeDefined();
    const emptyCeilingAfter = await museGate07Export(engine.client, {}, channelRef, emptyCeiling);
    expect(emptyCeilingAfter.records).toHaveLength(0);
    const grantAfter = await engine.client.call("vault.get", {
      entity_ref: minted.grant,
    } satisfies FacadeInput<"vault.get">);
    if (!grantAfter.value) throw new Error("Guest grant did not survive the restart");

    // Revoke, refused again: the same revoke a second time changes nothing.
    stage = "revoke guest grant";
    const revoked = await engine.client.call("vault.guests.revoke", {
      grant_ref: minted.grant,
    } satisfies FacadeInput<"vault.guests.revoke">);
    expect(revoked.changed).toBe(true);
    expect(revoked.grant_ref).toBe(minted.grant);
    expect(revoked.guest_ref).toBe(minted.guest_actor);
    stage = "repeat guest-grant revoke";
    const revokedAgain = await engine.client.call("vault.guests.revoke", {
      grant_ref: minted.grant,
    } satisfies FacadeInput<"vault.guests.revoke">);
  } catch (error) {
    primaryFailed = true;
    primary = error instanceof PublicHttpError ? new Error(
      `MUSE-GATE-07 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    ) : error;
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

// MUSE-GATE-08 - Generated and inferred input cannot raise authority or
// silently replace what the user stated.
// Promises: P-GATE-006 (an inferred preference or model hunch cannot
// authorize a Grant), P-GATE-023 (a content check can hold an automatic
// write at Proposed but cannot raise its authority ceiling), P-GATE-024
// (generated claims never silently supersede a user-stated claim) and
// P-GATE-025 (a generated disagreement remains beside the user-stated
// claim as Proposed).
// Doors used: vault.conversations.create, vault.witness, vault.get,
// vault.people.create, vault.structural.put + EngineFixture.pairActor
// (public setup only); vault.claims.upsert (user-stated and inferred
// writes) observed through vault.claims.list, vault.claims.history,
// vault.writes.pending and vault.receipts; vault.commit (the agent's
// generated disagreement); vault.claims.review / vault.claims.settle
// (the author may not settle its own proposal); vault.agents.verb_classes.get
// (pick a real verb class for the bound instead of inventing one);
// vault.consent.create_standing_grant / vault.consent.revoke observed
// through vault.consent.registry; vault.gate.policy.get and
// vault.gate.checker.get / vault.gate.checker.set (content-check bind).
// What stays unproved: the pass side of P-GATE-023 (a content check that
// passes still cannot lift an actor whose ceiling is Proposed) needs a
// verdict model that can pass, which the model-free deterministic fixture
// does not provide; a disagreement-card surface beyond the pending row
// and its decision receipt; and the reuse effect of the owner's standing
// grant on a later act (a generated claim would additionally need the
// manifest auto permit and auto_checker). See the report for details.

type MuseGate08ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
type MuseGate08PendingRow = FacadeResult<"vault.writes.pending">[number];
type MuseGate08CheckerBinding = NonNullable<FacadeResult<"vault.gate.checker.get">["binding"]>;
interface MuseGate08ConsentAttempt {
  readonly receipt?: FacadeResult<"vault.consent.create_standing_grant">;
  readonly error?: PublicHttpError;
}

const museGate08OccurredAt = 1769947200; // Public setup input, as in GATE-09.
const museGate08Predicate = "profile.preferred_display_name";
const museGate08InferredPredicate = "profile.inferred_standing_grant_preference";
const museGate08CheckerBasePredicate = "profile.checker_baseline_note";
const museGate08CheckerHeldPredicate = "profile.checker_held_note";
const museGate08CheckerFreePredicate = "profile.checker_free_note";

function museGate08IsProposed(approval: string): boolean {
  return approval.toLowerCase() === "proposed";
}
function museGate08IsLive(row: MuseGate08ClaimRow): boolean {
  const lifecycle = row.lifecycle.toLowerCase();
  return !lifecycle.includes("superseded") && !lifecycle.includes("retracted");
}
function museGate08ClaimIds(row: MuseGate08ClaimRow): string[] {
  return row.short_ref ? [row.claim_ref, row.short_ref] : [row.claim_ref];
}
function museGate08FindClaim(
  rows: readonly MuseGate08ClaimRow[], value: string,
): MuseGate08ClaimRow {
  const row = rows.find((candidate) => candidate.value === value);
  if (!row) throw new Error("MUSE-GATE-08 claim value was not read back by vault.claims.list");
  return row;
}
function museGate08PendingHas(
  rows: readonly MuseGate08PendingRow[], ids: readonly string[],
): boolean {
  return rows.some((row) => ids.includes(row.claim_ref));
}
function museGate08ExpectRefusalEnvelope(error: PublicHttpError): void {
  expect([401, 403]).toContain(error.reply.status);
  const wire = error.error;
  if (!wire) throw new Error("MUSE-GATE-08 refusal had no standard code/message envelope");
  expect(wire.code.length).toBeGreaterThan(0);
  expect(wire.message.length).toBeGreaterThan(0);
}
async function museGate08TryCreateStandingGrant(
  client: PublicHttpClient,
  input: FacadeInput<"vault.consent.create_standing_grant">,
): Promise<MuseGate08ConsentAttempt> {
  try {
    return { receipt: await client.call("vault.consent.create_standing_grant", input) };
  } catch (error) {
    if (error instanceof PublicHttpError) return { error };
    throw error;
  }
}

suite.test(test, "MUSE-GATE-08", "Generated and inferred input cannot raise authority or silently replace what the user stated", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-GATE-08", profile });
  let stage = "public setup";
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const suffix = secretHex(3);
    const personName = `Muse Gate08 Subject ${suffix}`;
    const userValue = `Maren ${suffix}`;
    const generatedValue = `Marenne ${suffix}`;
    const inferredValue = `inferred: the owner probably wants this agent to write ${museGate08Predicate} without asking (${suffix})`;
    const checkerBaseValue = `checker baseline ${suffix}`;
    const checkerHeldValue = `checker held ${suffix}`;
    const checkerFreeValue = `checker free ${suffix}`;
    redactor.add(personName, userValue, generatedValue, inferredValue,
      checkerBaseValue, checkerHeldValue, checkerFreeValue);
    const scope = await ownerBaseClaimScope(engine.client, ownerRef);

    // Public setup: one witnessed person as the claim subject, as in GATE-09.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: museGate08OccurredAt,
      occurred_end: museGate08OccurredAt, learned_at: museGate08OccurredAt,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witness = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: museGate08OccurredAt,
      messages: [{
        author: "user", message_type: "text",
        content: `This distinct person is ${personName}.`,
        is_visible: true, order: 0,
      }, {
        author: "assistant", message_type: "text",
        content: `Generated disagreement: the person's preferred display name is ${generatedValue}. ${inferredValue}`,
        is_visible: true, order: 1,
      }],
    } satisfies FacadeInput<"vault.witness">);
    const turn = await engine.client.call("vault.get", {
      entity_ref: witness.turn_short_id,
    } satisfies FacadeInput<"vault.get">);
    if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
      throw new Error("MUSE-GATE-08 witnessed TURN missing");
    }
    const created = await engine.client.call("vault.people.create", {
      identity: { name: personName },
      identity_evidence_refs: [turn.value.id_hex],
      occurred_at: museGate08OccurredAt,
    } satisfies FacadeInput<"vault.people.create">);
    const subjectRef = created.person.id_hex;
    expect((await engine.client.call("vault.get", {
      entity_ref: created.person.entity_ref,
    } satisfies FacadeInput<"vault.get">)).value?.kind).toBe("PERSON");

    // The writing agent, as in SECRETS-01: a public PERSON row, then a real
    // pairing whose credential holds core:read and core:write. That credential
    // scope is not consent authority: every consent-door refusal below is by
    // this already-scoped agent, not by an uncredentialled caller.
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: `Muse Gate08 Agent ${suffix}` },
      occurred_at: museGate08OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });
    const otherAgentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: `Muse Gate08 Non-grantee ${suffix}` },
      occurred_at: museGate08OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const otherAgent = await engine.pairActor({
      principalRef: otherAgentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    for (const record of [agentRecord, otherAgentRecord]) {
      expect((await engine.client.call("vault.get", { entity_ref: record.entity_ref })).value?.id_hex)
        .toBe(record.id_hex);
    }

    const museGate08ReadDisputed = async (): Promise<MuseGate08ClaimRow[]> => (
      await engine.client.call("vault.claims.list", {
        subject_ref: subjectRef, predicate: museGate08Predicate, limit: 100,
      } satisfies FacadeInput<"vault.claims.list">)
    ).value;
    const museGate08ReadPending = async (): Promise<MuseGate08PendingRow[]> =>
      engine.client.call("vault.writes.pending", {
        limit: 1000,
      } satisfies FacadeInput<"vault.writes.pending">);
    const museGate08ReadRegistryRefs = async (
      includeRevoked: boolean,
    ): Promise<Set<string>> => new Set((
      await engine.client.call("vault.consent.registry", {
        limit: 200, include_revoked: includeRevoked,
      } satisfies FacadeInput<"vault.consent.registry">)
    ).rows.map((row) => row.grant_ref));

    // P-GATE-024 / P-GATE-025, act one: the owner states a claim.
    stage = "owner user-stated claim upsert";
    const userWrite = await engine.client.call("vault.claims.upsert", {
      predicate: museGate08Predicate, subject_ref: subjectRef, value: userValue,
      confidence: 1, source: "user_stated", scope, occurred_at: museGate08OccurredAt,
    } satisfies FacadeInput<"vault.claims.upsert">);
    expect(userWrite.superseded_short_id ?? null).toBeNull();
    await engine.awaitReceipt(userWrite.receipt_ref);
    const userRow = museGate08FindClaim(await museGate08ReadDisputed(), userValue);
    expect(userRow.source).toBe("user_stated");
    expect(museGate08IsProposed(userRow.approval)).toBe(false);
    expect(museGate08IsLive(userRow)).toBe(true);

    // P-GATE-024 / P-GATE-025, act two: the agent commits a generated claim
    // that disagrees with the user-stated claim on the same subject and
    // predicate, at full confidence. Confidence and authorship buy it no
    // supersession: it must land beside the user-stated claim, Proposed.
    stage = "generated disagreement commit";
    const generatedOutcomes = await agent.client.call("vault.commit", {
      claims: [{
        predicate: museGate08Predicate, subject_ref: subjectRef, value: generatedValue,
        confidence: 1, source: "generated", scope, occurred_at: museGate08OccurredAt,
        evidence_turn_refs: [turn.value.id_hex],
      }],
    } satisfies FacadeInput<"vault.commit">);
    expect(generatedOutcomes).toHaveLength(1);
    const generatedOutcome = generatedOutcomes[0];
    if (!generatedOutcome || generatedOutcome.outcome !== "landed") {
      throw new Error(
        `MUSE-GATE-08 ENGINE DEFECT 2026-11-11: P-GATE-025 requires the evidence-backed generated disagreement to land Proposed beside the user's claim; the auto-supersede path instead requires the prior user's authorship (memory/authorship.rs:114-153); stage=${stage}; outcome=${JSON.stringify(generatedOutcome)}`,
      );
    }
    expect(museGate08IsProposed(generatedOutcome.approval)).toBe(true);
    expect(generatedOutcome.superseded_short_id ?? null).toBeNull();
    expect(generatedOutcome.claim_short_id).not.toBe(userWrite.claim_short_id);
    await engine.awaitReceipt(generatedOutcome.receipt_ref);

    const museGate08AssertBeside = async () => {
      const rows = await museGate08ReadDisputed();
      const user = museGate08FindClaim(rows, userValue);
      const generated = museGate08FindClaim(rows, generatedValue);
      expect(user.claim_ref).toBe(userRow.claim_ref);
      expect(museGate08IsLive(user)).toBe(true);
      expect(museGate08IsProposed(user.approval)).toBe(false);
      expect(generated.source).toBe("generated");
      expect(museGate08IsProposed(generated.approval)).toBe(true);
      const pending = await museGate08ReadPending();
      const generatedPending = pending.find((row) =>
        [...museGate08ClaimIds(generated), generatedOutcome.claim_short_id]
          .includes(row.claim_ref));
      if (!generatedPending) {
        throw new Error("MUSE-GATE-08 generated claim is missing from vault.writes.pending");
      }
      expect(museGate08PendingHas(pending,
        [...museGate08ClaimIds(user), userWrite.claim_short_id])).toBe(false);
      const history = await engine.client.call("vault.claims.history", {
        claim_ref: user.claim_ref,
      } satisfies FacadeInput<"vault.claims.history">);
      const historyUser = history.value.find((row) => row.claim_ref === user.claim_ref);
      if (!historyUser) {
        throw new Error("MUSE-GATE-08 user-stated claim is missing from its own history");
      }
      expect(museGate08IsLive(historyUser)).toBe(true);
      return { user, generated };
    };
    stage = "generated disagreement readback";
    let disputed = await museGate08AssertBeside();

    // The author of a proposal may not settle it: the agent approving its
    // own generated disagreement must not land it over the user's claim.
    stage = "review generated proposal and refuse self-settlement";
    const review = await engine.client.call("vault.claims.review", {
      claim_ref: disputed.generated.claim_ref,
    } satisfies FacadeInput<"vault.claims.review">);
    expect(museGate08ClaimIds(review.claim)).toContain(disputed.generated.claim_ref);
    let settleError: PublicHttpError | undefined = undefined;
    let settlement: FacadeResult<"vault.claims.settle"> | undefined = undefined;
    try {
      settlement = await agent.client.call("vault.claims.settle", {
        claim_ref: disputed.generated.claim_ref, review_id: review.review_id,
        decision: "approve",
      } satisfies FacadeInput<"vault.claims.settle">);
    } catch (error) {
      if (error instanceof PublicHttpError) settleError = error;
      else throw error;
    }
    if (settlement) {
      expect(settlement.verdict).toBe("rejected");
      expect(settlement.receipt_ref.length).toBeGreaterThan(0);
      expect(settlement.changes.every((change) => change.verdict === "rejected")).toBe(true);
    } else if (settleError) {
      museGate08ExpectRefusalEnvelope(settleError);
    } else {
      throw new Error("MUSE-GATE-08 agent settle attempt produced neither a settlement nor a refusal");
    }
    disputed = await museGate08AssertBeside();

    // P-GATE-006: an inferred preference is stored as data and nothing more.
    // Reading it back proves it landed; the registry must gain no grant.
    stage = "inferred preference cannot mint authority";
    const registryBeforeInferred = await museGate08ReadRegistryRefs(true);
    const inferredWrite = await agent.client.call("vault.claims.upsert", {
      predicate: museGate08InferredPredicate, subject_ref: ownerRef, value: inferredValue,
      confidence: 0.99, source: "inferred", scope, occurred_at: museGate08OccurredAt,
      evidence_turn_refs: [turn.value.id_hex],
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(inferredWrite.receipt_ref);
    const museGate08ReadInferred = async (): Promise<MuseGate08ClaimRow> =>
      museGate08FindClaim((
        await engine.client.call("vault.claims.list", {
          subject_ref: ownerRef, predicate: museGate08InferredPredicate, limit: 100,
        } satisfies FacadeInput<"vault.claims.list">)
      ).value, inferredValue);
    const inferredRow = await museGate08ReadInferred();
    expect(inferredRow.source).toBe("inferred");
    const registryAfterInferred = await museGate08ReadRegistryRefs(true);
    expect([...registryAfterInferred].filter(
      (ref) => !registryBeforeInferred.has(ref))).toEqual([]);

    // The bound uses a verb class the engine itself publishes, preferring the
    // one covering the claim-write verbs; the test invents no class name.
    stage = "discover standing-grant class";
    const verbClasses = await engine.client.call("vault.agents.verb_classes.get", {
    } satisfies FacadeInput<"vault.agents.verb_classes.get">);
    const grantClass = verbClasses.classes.find((row) =>
      row.verbs.includes("vault.commit") || row.verbs.includes("vault.claims.upsert")
    )?.name ?? verbClasses.classes[0]?.name;
    if (!grantClass) {
      throw new BlockedDoor("waits on a public verb-class row for a standing-grant bound (vault.agents.verb_classes.get returned no classes)");
    }
    const grantInput: FacadeInput<"vault.consent.create_standing_grant"> = {
      bound: {
        actor: agent.principalRef, class: grantClass,
        envelope: { project: scope.scope_project_id, audience: [subjectRef] },
      },
    };

    // With the inferred preference on record and no person's yes, the agent
    // creating a standing grant for itself confers nothing: the refusal is
    // receipted by the agent's own new receipt row, and the registry - read
    // through the owner - gains no row.
    stage = "agent self-grant refusal and call-receipt readback";
    const agentGrantAttempt = await museGate08TryCreateStandingGrant(agent.client, grantInput);
    const agentGrantAttemptError = agentGrantAttempt.error;
    if (!agentGrantAttemptError) {
      throw new Error("MUSE-GATE-08 agent self-grant was not refused");
    }
    museGate08ExpectRefusalEnvelope(agentGrantAttemptError);
    const refusalRef = agentGrantAttemptError.error?.receiptRef;
    if (typeof refusalRef !== "string" || refusalRef.length === 0) {
      throw new Error("MUSE-GATE-08 self-grant refusal carried no receiptRef");
    }
    const refusalReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", { receipt_ref: refusalRef }),
      (value) => value !== null,
      { label: "MUSE-GATE-08 self-grant refusal call receipt", timeoutMs: LIMITS.requestMs },
    );
    if (!refusalReceipt) throw new Error("MUSE-GATE-08 self-grant call receipt is absent");
    expect(refusalReceipt.actor_ref).toBe(agent.principalRef);
    expect(refusalReceipt.verb).toBe("vault.consent.create_standing_grant");
    if (refusalReceipt.outcome === "ok") throw new Error("MUSE-GATE-08 self-grant receipt reads ok");
    const refusalCode = agentGrantAttemptError.error?.code;
    if (typeof refusalCode !== "string") throw new Error("MUSE-GATE-08 self-grant refusal carried no error code");
    expect(refusalReceipt.outcome.refused.code).toBe(refusalCode);
    const registryAfterAgentAttempt = await museGate08ReadRegistryRefs(true);
    expect([...registryAfterAgentAttempt].filter(
      (ref) => !registryAfterInferred.has(ref))).toEqual([]);

    // The person's yes: the owner creates the same bounded grant. The grant
    // is then readable in the registry, an action-domain row for the chosen
    // verb class - the control that proves the bound itself was well-formed.
    stage = "owner standing grant and registry readback";
    const ownerGrant = await engine.client.call("vault.consent.create_standing_grant", grantInput);
    const grantRef = ownerGrant.grant_ref;
    if (!grantRef) {
      throw new Error("MUSE-GATE-08 owner's create_standing_grant returned no grant_ref");
    }
    const registryWithGrant = await engine.client.call("vault.consent.registry", {
      limit: 200, include_revoked: false,
    } satisfies FacadeInput<"vault.consent.registry">);
    const grantRow = registryWithGrant.rows.find((row) => row.grant_ref === grantRef);
    if (!grantRow) {
      throw new Error("MUSE-GATE-08 owner's standing grant is missing from the consent registry");
    }
    expect(grantRow.domain).toBe("action");
    expect(grantRow.class).toBe(grantClass);

    // A grantee may renounce its own Grant (P-GATE-010). An unrelated
    // non-grantee's revoke attempt leaves it live; the owner's revoke ends it.
    stage = "non-grantee cannot revoke owner grant";
    let agentRevokeError: PublicHttpError | undefined = undefined;
    try {
      await otherAgent.client.call("vault.consent.revoke", {
        grant: grantRef,
      } satisfies FacadeInput<"vault.consent.revoke">);
    } catch (error) {
      if (error instanceof PublicHttpError) agentRevokeError = error;
      else throw error;
    }
    if (!agentRevokeError) throw new Error("MUSE-GATE-08 non-grantee revoked the owner's grant");
    museGate08ExpectRefusalEnvelope(agentRevokeError);
    expect((await museGate08ReadRegistryRefs(false)).has(grantRef)).toBe(true);
    stage = "owner grant revoke and registry readback";
    const ownerRevoke = await engine.client.call("vault.consent.revoke", {
      grant: grantRef,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect((await museGate08ReadRegistryRefs(false)).has(grantRef)).toBe(false);
    expect((await museGate08ReadRegistryRefs(true)).has(grantRef)).toBe(true);

    // Restart: the user-stated claim is still live, the generated disagreement
    // still waits Proposed beside it, the inferred preference is still only a
    // claim, and the revoked grant does not return. An agent that has lost
    // its grant is refused again at its next use of the consent door.
    stage = "restart claim and grant readback";
    await engine.restart();
    disputed = await museGate08AssertBeside();
    expect((await museGate08ReadInferred()).source).toBe("inferred");
    expect((await museGate08ReadRegistryRefs(false)).has(grantRef)).toBe(false);
    expect((await museGate08ReadRegistryRefs(true)).has(grantRef)).toBe(true);
    const registryBeforeRetry = await museGate08ReadRegistryRefs(true);
    const agentGrantRetry = await museGate08TryCreateStandingGrant(agent.client, grantInput);
    const agentGrantRetryError = agentGrantRetry.error;
    if (!agentGrantRetryError) throw new Error("MUSE-GATE-08 post-revoke agent self-grant was not refused");
    museGate08ExpectRefusalEnvelope(agentGrantRetryError);
    expect([...(await museGate08ReadRegistryRefs(true))].filter(
      (ref) => !registryBeforeRetry.has(ref))).toEqual([]);

    // P-GATE-023, the hold direction: first prove the owner's ordinary
    // user-stated write is automatic without an enforced checker.
    const museGate08WriteOwnerClaim = async (predicate: string, value: string) => {
      const write = await engine.client.call("vault.claims.upsert", {
        predicate, subject_ref: subjectRef, value,
        confidence: 1, source: "user_stated", scope, occurred_at: museGate08OccurredAt,
      } satisfies FacadeInput<"vault.claims.upsert">);
      await engine.awaitReceipt(write.receipt_ref);
      return write;
    };
    const museGate08ReadSingle = async (
      predicate: string, value: string,
    ): Promise<MuseGate08ClaimRow> => museGate08FindClaim((
      await engine.client.call("vault.claims.list", {
        subject_ref: subjectRef, predicate, limit: 100,
      } satisfies FacadeInput<"vault.claims.list">)
    ).value, value);
    stage = "checker baseline automatic claim";
    const checkerBaseWrite = await museGate08WriteOwnerClaim(
      museGate08CheckerBasePredicate, checkerBaseValue);
    const checkerBaseRow = await museGate08ReadSingle(
      museGate08CheckerBasePredicate, checkerBaseValue);
    expect(museGate08IsProposed(checkerBaseWrite.approval)).toBe(false);
    expect(museGate08IsProposed(checkerBaseRow.approval)).toBe(false);
    expect(museGate08PendingHas(await museGate08ReadPending(),
      [...museGate08ClaimIds(checkerBaseRow), checkerBaseWrite.claim_short_id])).toBe(false);

    // Bind the verdict role only from names the vault itself publishes: an
    // existing checker binding, else the default manifest's auto_checker.
    // The deterministic fixture serves no model, so an enforced check at the
    // "certain" floor cannot pass and must fail closed to Proposed.
    stage = "discover configured checker model";
    const checkerBefore = await engine.client.call("vault.gate.checker.get", {
    } satisfies FacadeInput<"vault.gate.checker.get">);
    const baselineBinding = checkerBefore.binding ?? null;
    const policy = await engine.client.call("vault.gate.policy.get", {
    } satisfies FacadeInput<"vault.gate.policy.get">);
    const defaultManifest = policy.manifests.find(
      (row) => row.manifest_ref === policy.default_manifest_ref) ?? policy.manifests[0];
    const checkerModel = baselineBinding?.model
      ?? defaultManifest?.manifest.auto_checker ?? null;
    if (!checkerModel) {
      throw new BlockedDoor("waits on a named verdict model for vault.gate.checker.set (the checker binding and the default manifest auto_checker are both empty in the deterministic fixture)");
    }
    const checkerSlot: MuseGate08CheckerBinding["slot"] = baselineBinding?.slot ?? "llm";
    const enforceBinding: MuseGate08CheckerBinding = {
      model: checkerModel, slot: checkerSlot, floor: "certain", mode: "enforce",
    };

    // The agent whose writes the checker would judge cannot rebind the
    // checker itself; the owner's read shows the binding unchanged.
    stage = "agent cannot rebind checker";
    let checkerError: PublicHttpError | undefined = undefined;
    try {
      await agent.client.call("vault.gate.checker.set", {
        binding: enforceBinding,
      } satisfies FacadeInput<"vault.gate.checker.set">);
    } catch (error) {
      if (error instanceof PublicHttpError) checkerError = error;
      else throw error;
    }
    if (!checkerError) {
      throw new Error("MUSE-GATE-08 agent was able to set the gate checker binding");
    }
    museGate08ExpectRefusalEnvelope(checkerError);
    expect((await engine.client.call("vault.gate.checker.get", {
    } satisfies FacadeInput<"vault.gate.checker.get">)).binding ?? null).toEqual(baselineBinding);

    stage = "owner checker enforce binding and readback";
    const checkerSet = await engine.client.call("vault.gate.checker.set", {
      binding: enforceBinding,
    } satisfies FacadeInput<"vault.gate.checker.set">);
    expect(checkerSet.binding.mode).toBe("enforce");
    const checkerEnforced = await engine.client.call("vault.gate.checker.get", {
    } satisfies FacadeInput<"vault.gate.checker.get">);
    expect(checkerEnforced.binding?.mode).toBe("enforce");
    expect(checkerEnforced.binding?.floor).toBe("certain");

    // The same ordinary owner write that was automatic above is now held at
    // Proposed by content alone - and the hold is the checker's whole power.
    stage = "checker holds automatic write";
    const heldWrite = await museGate08WriteOwnerClaim(
      museGate08CheckerHeldPredicate, checkerHeldValue);
    expect(museGate08IsProposed(heldWrite.approval)).toBe(true);
    const heldRow = await museGate08ReadSingle(
      museGate08CheckerHeldPredicate, checkerHeldValue);
    expect(museGate08IsProposed(heldRow.approval)).toBe(true);
    expect(museGate08PendingHas(await museGate08ReadPending(),
      [...museGate08ClaimIds(heldRow), heldWrite.claim_short_id])).toBe(true);

    // Restoring the prior binding (or shadow, the non-enforcing mode, when
    // there was none) makes the same write automatic again: only the
    // owner's policy act changed the outcome, never the checked content.
    const restoredBinding: MuseGate08CheckerBinding = baselineBinding ?? {
      model: checkerModel, slot: checkerSlot, floor: "certain", mode: "shadow",
    };
    stage = "restore checker binding";
    await engine.client.call("vault.gate.checker.set", {
      binding: restoredBinding,
    } satisfies FacadeInput<"vault.gate.checker.set">);
    expect((await engine.client.call("vault.gate.checker.get", {
    } satisfies FacadeInput<"vault.gate.checker.get">)).binding?.mode).toBe(restoredBinding.mode);
    stage = "restored checker permits automatic write";
    const freeWrite = await museGate08WriteOwnerClaim(
      museGate08CheckerFreePredicate, checkerFreeValue);
    expect(museGate08IsProposed(freeWrite.approval)).toBe(false);
    const freeRow = await museGate08ReadSingle(
      museGate08CheckerFreePredicate, checkerFreeValue);
    expect(museGate08IsProposed(freeRow.approval)).toBe(false);
    expect(museGate08PendingHas(await museGate08ReadPending(),
      [...museGate08ClaimIds(freeRow), freeWrite.claim_short_id])).toBe(false);

    await engine.artifacts.json("muse-gate08-summary.json", {
      subject_ref: subjectRef,
      user_claim: disputed.user.claim_ref,
      generated_claim: disputed.generated.claim_ref,
      generated_approval: disputed.generated.approval,
      grant_ref: grantRef,
      grant_class: grantClass,
      checker_model: checkerModel,
      held_claim_short_id: heldWrite.claim_short_id,
    });
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-GATE-08 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    if (error instanceof Error && error.message.startsWith("MUSE-GATE-08 ENGINE DEFECT 2026-11-11:")) throw error;
    throw new Error(`MUSE-GATE-08 ${stage}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  } finally {
    await engine.close();
  }
});

// MUSE-GATE-09 -- A blocked act names its blocker only to a reader who may
// see that policy.
// Promises:
// - P-GATE-026 (MUST): A blocked act names its blocking level, row, and role
//   only when the reader can see that policy.
// - P-GATE-027 (MUST): A hidden policy restriction is reported as blocked by
//   policy without revealing the hidden record.
// Canon: DEC-0006 #proposals, one settlement receipt per proposal: "A
// rejection names the level, row and role that blocked it only when the
// reader's own box admits that record; otherwise it says 'blocked by
// policy'."
//
// Doors examined in the generated facade (engine main e79eb76df3e) and why
// none of them can drive the core act today:
// - vault.runs.settlement -> RunSettlement, kind "ProposalOutcome". This is
//   the register's named door, but its typed result carries no level, role,
//   or rejection-diagnostic field (answered_by is {word_ref} | {row} |
//   {grant}; reason is owner_approved | owner_rejected; summary is a free
//   string), and the verb is owner-only. A second, non-owner reader cannot
//   read a redacted "blocked by policy" form through it.
// - vault.runs.settle is also owner-only and settles by the owner's word.
//   No typed door produces a rejection answered first by a policy row.
// - vault.claims.settle -> ClaimSettlement has the same gap: answered_by is
//   a person's word or a Grant, with no level/row/role diagnostic, and
//   there is no proposer-side read of that settlement.
// - vault.gate.policy.get is owner-only; vault.gate.policy.put installs a
//   PolicyManifest whose typed axes are only criticality/sensitivity and a
//   ceiling of auto | proposed. There is no typed reject/block row to
//   install, so a policy-row-answered rejection cannot be set up.
// - vault.receipts returns MemoryReceipt rows. The typed row has no
//   diagnostic fields; its only extensible part is an untyped
//   Record<string, string> of fields, whose keys are not part of the typed
//   surface and must not be guessed.
// - vault.explain.gate cites policy rows behind a gate receipt and answers
//   none to a caller who may not read it. It is not a ProposalOutcome, it
//   carries no level or role, and "none" is not the canon's "blocked by
//   policy" human line, so it cannot stand in for P-GATE-027.
// - The only typed level/row/role shape on the surface is the error-side
//   MemoryPolicyDenial {level, row_ref, role, exception_proposal}, carried
//   optionally by MemoryError. No facade verb returns it as a result, and
//   no verb in the typed catalog creates or hides a world/policy record
//   for one reader while showing it to another (there is no vault.worlds
//   verb; the only world-privacy verbs carry a federation leg).
//
// Typed design notes for the door this case waits on (canon shapes, not new
// wire DTOs to guess at): a reader-projected ProposalOutcome read, admitted
// to the proposal's opener and to readers whose Grant/Scope admits the
// proposal -- not owner-only -- returning the current RunSettlement shape
// plus the canon diagnostic when the reader's box admits the policy
// record, and otherwise the same rejected outcome whose one human line is
// exactly "blocked by policy", with no level, row, role, exception row, or
// hidden record identifier anywhere in the result. It also needs a
// producer: a policy row that can answer a proposal first and reject it
// (answered_by naming that row id@version), plus a typed way to place one
// such row/record outside the second reader's box.
type museGate09CurrentRunOutcome = FacadeResult<"vault.runs.settlement">;
type museGate09CurrentRunOutcomeRead = FacadeInput<"vault.runs.settlement">;
type museGate09CurrentClaimOutcome = FacadeResult<"vault.claims.settle">;
type museGate09CurrentPolicyPut = FacadeInput<"vault.gate.policy.put">;
type museGate09NeededPolicyDenial = {
  level: string;
  row_ref: string;
  role: string;
  exception_proposal: { action: string; row_ref: string; required_role: string };
};
type museGate09NeededVisibleRunOutcome = museGate09CurrentRunOutcome & {
  policy_denial: museGate09NeededPolicyDenial;
};
type museGate09NeededHiddenRunOutcome = museGate09CurrentRunOutcome & {
  policy_denial?: null;
  summary: "blocked by policy";
};
type museGate09NeededReaderOutcome =
  | museGate09NeededVisibleRunOutcome
  | museGate09NeededHiddenRunOutcome;

// Planned journey once that door exists (act; observe through a second
// door; refuse the wrong actor kind, with its receipt read back; restart):
// the owner installs the blocking row; a paired agent opens the proposal
// the row rejects; the owner reads the ProposalOutcome back through
// vault.receipts and through the settlement read and sees level/row/role;
// an agent with no policy-read grant reads the same outcome and sees only
// "blocked by policy"; the owner mints that agent a policy-read Grant and
// it then sees the diagnostic; the owner revokes the Grant and its next
// read is hidden again; the opener's own settle attempt is refused in the
// standard envelope and leaves the proposal still pending on read-back;
// after engine.restart() both reader projections read back unchanged.
suite.todo(test, "MUSE-GATE-09", "waits on a reader-projected ProposalOutcome read (typed level/row/role diagnostic for admitted readers, 'blocked by policy' for hidden ones) and a policy-row-answered rejection producer");

// MUSE-GATE-10 — PARTIAL. Promise ids: P-GATE-031, P-GATE-032, P-GATE-033.
// Proved here: P-GATE-033 only. A wire-rate threshold crossing raises a typed
// health question rather than refusing the call for rate
// (ARCH-0044 C5: "The wire never refuses a call for rate"; "Crossing one raises
// a typed question"). Doors used: vault.wire_health.thresholds.get/set (owner
// host doors), vault.claims.upsert as the burst verb read back through
// vault.claims.list, GET /v1/owner/wire-health for the typed check (the native
// route and wire key GATE-09 in this file already uses), vault.authority.audit
// and POST /v1/core/slips/revoke for the wrong-kind / revoked-slip legs.
// Not proved: P-GATE-031 (no typed door binds MCP code mode in the deterministic
// harness — canon needs a generative seat plus a [models.code_mode] prompt
// package no allowed source names — and no public door holds a run mid-step
// while the owner revokes its slip) and P-GATE-032 (ConnectorCallRequest
// carries no manifest/basis/hash a stale render could present, and the refused
// ConnectorCallReply carries no typed current manifest hash). The report names
// the missing doors. The facade verb also called execute_code is the isolated
// foreign-code tier (no credentials lent), not the MCP code-run slip door, so
// it is deliberately not used as a substitute.
type MuseGate10AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type MuseGate10HealthCrossing = {
  per_verb: number;
  per_actor: number;
  verbs: { verb: string; calls: number }[];
  actors: { actor: string; calls: number }[];
  crossed: { actors: string[]; verbs: string[] };
};
type MuseGate10HealthCheck = {
  subject: string;
  source: string;
  crossing: MuseGate10HealthCrossing;
  state: { state: "held" }
    | { state: "asked" | "answered"; question: string; unit: string }
    | { state: "superseded"; by: string };
};
type MuseGate10HealthList = { checks: MuseGate10HealthCheck[] };
interface MuseGate10Person {
  readonly idHex: string;
  readonly value: string;
}
// Wire-health verb key for one facade call: METHOD plus matched path, the same
// key GATE-09 in this file reads back from GET /v1/owner/wire-health.
const museGate10UpsertVerb = "POST /v1/core/facade/vault.claims.upsert";

async function museGate10AuditRows(
  client: EngineFixture["client"],
): Promise<MuseGate10AuditRow[]> {
  const rows: MuseGate10AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museGate10MintedSlip(
  before: readonly MuseGate10AuditRow[],
  after: readonly MuseGate10AuditRow[],
  holder: string,
): MuseGate10AuditRow {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  expect(row.subject_ref).toMatch(/^[a-f0-9]{64}$/);
  return row;
}

function museGate10IsBurstCheck(
  check: MuseGate10HealthCheck,
  baselineSubjects: ReadonlySet<string>,
  ownerHex: string,
): boolean {
  if (baselineSubjects.has(check.subject)) return false;
  if (check.source !== "wire") return false;
  return check.crossing.crossed.actors.includes(ownerHex)
    && check.crossing.crossed.verbs.includes(museGate10UpsertVerb);
}

async function museGate10ExpectClaims(
  client: EngineFixture["client"],
  persons: readonly MuseGate10Person[],
  predicate: string,
): Promise<void> {
  for (const person of persons) {
    const list = await client.call("vault.claims.list", {
      subject_ref: person.idHex, predicate, limit: 100,
    } satisfies FacadeInput<"vault.claims.list">);
    expect(list.value).toHaveLength(1);
    expect(list.value[0]!.subject_ref).toBe(person.idHex);
    expect(list.value[0]!.predicate).toBe(predicate);
    expect(list.value[0]!.value).toBe(person.value);
  }
}

suite.test(test, "MUSE-GATE-10", "A wire-rate threshold crossing raises a typed health question and still serves every burst write", async () => {
  const startedAt = performance.now();
  let stage = "public setup";
  const engine = await EngineFixture.start({ id: "MUSE-GATE-10", profile });
  let primaryFailed = false;
  let primary: unknown;
  try {
    const ownerHex = engine.pairedActor.principalRef;
    const occurred = 1769947200; // Fixed public setup time, as in GATE-09 in this file.
    const predicate = "profile.harbour_note";
    const count = 4;
    const thresholds: FacadeInput<"vault.wire_health.thresholds.set"> = {
      window_secs: 60, per_verb: 3, per_actor: 3,
    };

    stage = "read owner wire thresholds";
    const baselineThresholds = await engine.client.call("vault.wire_health.thresholds.get", {
    } satisfies FacadeInput<"vault.wire_health.thresholds.get">);

    // Wrong actor kind: a read-only agent may not replace the owner's wire
    // thresholds, and the refused write must not land.
    const auditBeforePair = await museGate10AuditRows(engine.client);
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Gate Ten Agent" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });
    stage = "agent threshold change refusal";
    const refusedSet = await agent.client.raw<{ error?: { code?: unknown; message?: unknown } }>(
      "POST", "/v1/core/facade/vault.wire_health.thresholds.set",
      { window_secs: 60, per_verb: 999, per_actor: 999 },
    );
    expect(refusedSet.status).toBe(403);
    const refusedSetCode = refusedSet.body.error?.code;
    const refusedSetMessage = refusedSet.body.error?.message;
    expect(typeof refusedSetCode === "string" && refusedSetCode.length > 0).toBe(true);
    expect(typeof refusedSetMessage === "string" && refusedSetMessage.length > 0).toBe(true);
    expect(await engine.client.call("vault.wire_health.thresholds.get", {
    } satisfies FacadeInput<"vault.wire_health.thresholds.get">)).toEqual(baselineThresholds);

    // The same agent then loses its slip mid-flow: the owner revokes it through
    // the public slips door and the dead credential is refused at its next use.
    stage = "revoke agent slip and read audit";
    const issued = museGate10MintedSlip(
      auditBeforePair, await museGate10AuditRows(engine.client), agent.principalRef,
    );
    const slipId = issued.subject_ref!;
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke", { slip_id: Array.from(Buffer.from(slipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const deadRead = await agent.client.raw<{ error?: { code?: unknown; message?: unknown } }>(
      "POST", "/v1/core/facade/vault.wire_health.thresholds.get", {},
    );
    expect(deadRead.status).toBe(401);
    const deadCode = deadRead.body.error?.code;
    expect(typeof deadCode === "string" && deadCode.length > 0).toBe(true);
    const auditAfterRevoke = await museGate10AuditRows(engine.client);
    expect(auditAfterRevoke.some((row) => row.source_op === "slip_revoke"
      && row.subject_ref === slipId && row.fold_valid)).toBe(true);

    // Burst subjects: distinct persons, each evidenced by its own witnessed turn.
    stage = "create distinct evidenced burst subjects";
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const scope = await ownerBaseClaimScope(engine.client, ownerHex);
    const persons: MuseGate10Person[] = [];
    for (let i = 0; i < count; i++) {
      const name = `Gate Ten Person ${i}`;
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
      const got = await engine.client.call("vault.get", {
        entity_ref: created.person.entity_ref,
      } satisfies FacadeInput<"vault.get">);
      expect(got.value?.kind).toBe("PERSON");
      persons.push({ idHex: created.person.id_hex, value: `Harbour lantern note ${i}` });
    }
    expect(new Set(persons.map((person) => person.idHex)).size).toBe(count);

    // Act: the owner installs low detection thresholds; the receipt names the
    // previous and installed rows, and a second door reads the same rows back.
    stage = "install and read detection thresholds";
    const healthBaseline = (await engine.client.request<MuseGate10HealthList>(
      "GET", "/v1/owner/wire-health",
    )).body;
    const baselineSubjects = new Set(healthBaseline.checks.map((check) => check.subject));
    const setReceipt = await engine.client.call("vault.wire_health.thresholds.set", thresholds);
    expect(setReceipt.thresholds).toEqual(thresholds);
    expect(await engine.client.call("vault.wire_health.thresholds.get", {
    } satisfies FacadeInput<"vault.wire_health.thresholds.get">)).toEqual(thresholds);

    // Cross both rows with ordinary writes. No write may be refused for rate.
    stage = "owner ordinary burst upserts";
    const inputs: FacadeInput<"vault.claims.upsert">[] = persons.map((person) => ({
      predicate,
      subject_ref: person.idHex,
      value: person.value,
      confidence: 1,
      source: "user_stated",
      scope,
      occurred_at: occurred,
    }));
    const settled = await Promise.allSettled(
      inputs.map((input) => engine.client.call("vault.claims.upsert", input)),
    );
    const fulfilled: FacadeResult<"vault.claims.upsert">[] = [];
    const rejected: { index: number; status: number | null; code: string; message: string; suggestion: string }[] = [];
    settled.forEach((row, index) => {
      if (row.status === "fulfilled") {
        fulfilled.push(row.value);
      } else if (row.reason instanceof PublicHttpError) {
        rejected.push({ index, status: row.reason.reply.status,
          code: row.reason.error?.code ?? "<none>",
          message: row.reason.error?.message ?? row.reason.message,
          suggestion: row.reason.error?.suggestions?.[0] ?? "<none>" });
      } else {
        rejected.push({ index, status: null, code: "UNKNOWN",
          message: row.reason instanceof Error ? row.reason.message : String(row.reason),
          suggestion: "<none>" });
      }
    });
    await engine.artifacts.json("muse-gate10-burst-outcomes.json", {
      receipts: fulfilled.map((receipt) => receipt.receipt_ref), rejected,
    });
    if (rejected.length > 0) {
      throw new Error(`MUSE-GATE-10 ${stage}: ${JSON.stringify(rejected)}`);
    }
    expect(rejected).toHaveLength(0);
    expect(fulfilled).toHaveLength(count);
    for (const receipt of fulfilled) {
      expect(receipt.receipt_ref.length).toBeGreaterThan(0);
      await engine.awaitReceipt(receipt.receipt_ref);
    }

    // Observe through the health door: the crossing raises a typed question
    // (asked, or answered once the ladder has it) for this actor and verb.
    const museGate10Question = (start: MuseGate10HealthCheck, list: MuseGate10HealthList): MuseGate10HealthCheck | null => {
      const bySubject = new Map(list.checks.map((check) => [check.subject, check]));
      const visited = new Set<string>();
      let current: MuseGate10HealthCheck | undefined = start;
      while (current && !visited.has(current.subject)) {
        visited.add(current.subject);
        if (current.state.state === "asked" || current.state.state === "answered") {
          return current.state.question.length > 0 && current.state.unit.length > 0 ? current : null;
        }
        if (current.state.state !== "superseded") return null;
        current = bySubject.get(current.state.by);
      }
      return null;
    };
    stage = "read typed health question for burst crossing";
    const health = await awaitPublic(
      async () => (await engine.client.request<MuseGate10HealthList>(
        "GET", "/v1/owner/wire-health",
      )).body,
      (list) => {
        const burst = list.checks.filter((check) => museGate10IsBurstCheck(check, baselineSubjects, ownerHex));
        return burst.length > 0 && burst.every((check) => museGate10Question(check, list) !== null);
      },
      { label: "MUSE-GATE-10 wire-rate crossing raises a typed health question (including superseded revisions)",
        timeoutMs: Math.max(1, LIMITS.flowMs - (performance.now() - startedAt) - LIMITS.readyMs) },
    );
    const burstChecks = health.checks.filter(
      (check) => museGate10IsBurstCheck(check, baselineSubjects, ownerHex),
    );
    expect(burstChecks.length).toBeGreaterThanOrEqual(1);
    for (const check of burstChecks) {
      expect(check.crossing.per_verb).toBe(thresholds.per_verb);
      expect(check.crossing.per_actor).toBe(thresholds.per_actor);
      expect(check.crossing.verbs.some(
        (row) => row.verb === museGate10UpsertVerb && row.calls > thresholds.per_verb,
      )).toBe(true);
      expect(check.crossing.actors.some(
        (row) => row.actor === ownerHex && row.calls > thresholds.per_actor,
      )).toBe(true);
      const question = museGate10Question(check, health);
      if (!question) throw new Error(`MUSE-GATE-10 crossing has no typed question: ${JSON.stringify(check)}`);
      expect(museGate10IsBurstCheck(question, baselineSubjects, ownerHex)).toBe(true);
      expect(question.state.state === "asked" || question.state.state === "answered").toBe(true);
    }
    await engine.artifacts.json("muse-gate10-health.json", health);

    // Every burst write reads back through the claims door, before and after a
    // restart; the revoked slip stays dead across the restart too.
    stage = "read burst claims before and after restart";
    await museGate10ExpectClaims(engine.client, persons, predicate);
    await engine.restart();
    await museGate10ExpectClaims(engine.client, persons, predicate);
    const deadAfterRestart = await agent.client.raw<{ error?: { code?: unknown } }>(
      "POST", "/v1/core/facade/vault.wire_health.thresholds.get", {},
    );
    expect(deadAfterRestart.status).toBe(401);
  } catch (error) {
    primaryFailed = true;
    primary = error instanceof PublicHttpError ? new Error(
      `MUSE-GATE-10 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    ) : error;
  } finally {
    try {
      await engine.close();
    } catch (cleanup) {
      if (primaryFailed) {
        throw new AggregateError([primary, cleanup], `${String(primary)}; cleanup: ${String(cleanup)}`);
      }
      throw cleanup;
    }
    if (primaryFailed) throw primary;
  }
});

function museGate11ExpectNoValues(value: unknown, values: readonly string[]): void {
  const text = JSON.stringify(value) ?? "";
  // One boolean assertion: a failure diff must never print a fixture value.
  expect(values.every((item) => item.length > 0
    && !text.includes(item)
    && !text.includes(Buffer.from(item).toString("base64")))).toBe(true);
}

function museGate11WireError(body: unknown): { code: string; message: string } {
  const root = body && typeof body === "object" && !Array.isArray(body)
    ? body as Record<string, unknown> : {};
  const inner = root.error && typeof root.error === "object" && !Array.isArray(root.error)
    ? root.error as Record<string, unknown> : root;
  return {
    code: typeof inner.code === "string" ? inner.code : "",
    message: typeof inner.message === "string" ? inner.message : "",
  };
}

function museGate11GrantRef(
  receipt: FacadeResult<"vault.consent.create_standing_grant">,
): string {
  if (!receipt.grant_ref) {
    throw new Error(`create_standing_grant returned no grant_ref (outcome=${receipt.outcome}, reason=${receipt.reason_code})`);
  }
  return receipt.grant_ref;
}

function museGate11CanVerdict(answer: FacadeResult<"can">): string {
  if (!("verdict" in answer)) {
    throw new Error("can(outbound_schedule effect) returned a task preflight, not an effect verdict");
  }
  return answer.verdict;
}

/*
 * MUSE-GATE-11 — PARTIAL subset of P-GATE-029 and P-GATE-030.
 *
 * P-GATE-029: cross-vault secret sharing authorizes use without transferring
 * custody of the secret value (ARCH-0069 #cross-vault).
 * P-GATE-030: a mixed private-content send must pass both the disclosure and
 * action checks (DEC-0006 #model, invariant 4).
 *
 * Doors used: vault.structural.put + pairActor (agent setup);
 * vault.secrets.register / vault.secrets.custody.get / reveal.describe /
 * self.use / reveal / reveal.wait / vault.secrets.revoke (shared secret use);
 * vault.claims.upsert / vault.claims.list (private content);
 * connector.list (live send-capable channel discovery);
 * vault.consent.create_standing_grant / vault.consent.registry /
 * vault.consent.revoke (disjoint action and disclosure grants);
 * can (outbound-schedule effect preflight) and connector.outbound.schedule.
 *
 * Unproved here: literal use from a second live vault with no custody
 * replication, because no typed cross-vault secret-use share/mint door was
 * found in the facade and this file runs one slot (EngineFixture peers need
 * two); delivery to a real channel; a typed read-back of an outbound intent
 * by intent_ref; and a refused-call receipt row for the two raw refusals.
 * The report names the candidate doors.
 */
suite.test(test, "MUSE-GATE-11", "A bound secret is usable through self.use without revealing its value, and a private outbound send is allowed only with both action and disclosure standing grants", async () => {
  // Generated fixture values only. Redact every secret and sentinel before
  // its first use anywhere, including in artifacts and assertion text.
  const probeSecret = `muse-gate11-probe-secret-${secretHex(16)}`;
  const sharedSecret = `muse-gate11-shared-secret-${secretHex(16)}`;
  const privateSentinel = `MUSE-GATE11-PRIVATE-CONTENT-${secretHex(8)}`;
  const secretValues = [probeSecret, sharedSecret];
  for (const value of [...secretValues, privateSentinel]) {
    redactor.add(value, Buffer.from(value).toString("base64"));
  }
  const probeSecretB64 = Buffer.from(probeSecret).toString("base64");
  const sharedSecretB64 = Buffer.from(sharedSecret).toString("base64");
  const occurred = 1_769_947_200;
  // Use the shipped native-mail T0 operation against a scripted loopback
  // JMAP origin. The model sees the result, never the credential.
  const secretOperation = "native_mail.jmap";
  const learnedEffector = "connector:native_mail"; // SECRET_USE_OPERATIONS' fixed T0 effector.

  let stage = "scripted native-mail custody-use setup";
  let primaryFailed = false;
  let primary: unknown;
  const provider = await ScriptedProviders.start({ id: "muse-gate11-native-mail", origins: ["mail"], steps: [] });
  const enqueueMailCheck = (tag: string) => {
    provider.enqueue({
      id: `${tag}-session`, origin: "mail", role: "native-mail", purpose: "T0 credential use JMAP discovery",
      request: { method: "GET", path: "/.well-known/jmap" },
      response: { kind: "json", body: { apiUrl: "/jmap", downloadUrl: "/download/{blobId}", capabilities: {
        "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:submission": {}, "urn:stalwart:jmap": {},
      } } },
    });
    provider.enqueue({
      id: `${tag}-domain`, origin: "mail", role: "native-mail", purpose: "T0 credential use domain check",
      request: { method: "POST", path: "/jmap", fields: {
        methodCalls: [["x:Domain/get", { accountId: "0", ids: ["gate11-domain"],
          properties: ["id", "name", "isEnabled", "catchAllAddress", "memberTenantId"] }, "mail"]],
      } },
      response: { kind: "json", body: { methodResponses: [["x:Domain/get", { list: [{
        id: "gate11-domain", name: "gate11.example", isEnabled: true,
        catchAllAddress: null, memberTenantId: null,
      }] }, "mail"]] } },
    });
  };
  const engine = await EngineFixture.start({ id: "MUSE-GATE-11", profile,
    serverConfig: `[native_mail]
session_url = "${provider.urls.mail}/.well-known/jmap"
domain = "gate11.example"
domain_id = "gate11-domain"
`,
  });
  try {
    const ownerRef = engine.pairedActor.principalRef;

    // Public setup only: three PERSON rows. Pairing supplies no consent,
    // secret binding or channel grant; those arrive only through the
    // typed grant and custody doors below.
    const senderRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Gate11 Sender Agent" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const noGrantRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Gate11 Unrelated Agent" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const recipientRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Gate11 Recipient" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    for (const record of [senderRecord, noGrantRecord, recipientRecord]) {
      const readback = await engine.client.call("vault.get", { entity_ref: record.entity_ref });
      expect(readback.value?.kind).toBe("PERSON");
      expect(readback.value?.id_hex).toBe(record.id_hex);
    }
    const sender = await engine.pairActor({
      principalRef: senderRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });
    const noGrantAgent = await engine.pairActor({
      principalRef: noGrantRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });
    const recipientRef = recipientRecord.id_hex;

    // ------------------------------------------------------------------
    // P-GATE-029 subset, custody side. Canon's custody classes include
    // cross-vault: never replicated, doored USE by receipted grants, and
    // the value stays in the owner's custody.
    // ------------------------------------------------------------------
    const custodyHandle = async (secretId: string): Promise<string> => {
      const exported = await engine.client.call("vault.export", { format: "archive", include_secrets: false, delivery: "inline" });
      if (!("archive" in exported)) throw new Error("MUSE-GATE-11 inline custody export returned a transfer");
      const zip = Buffer.from(exported.archive, "base64");
      let end = zip.length - 22;
      for (; end >= Math.max(0, zip.length - 65_557); end--) {
        if (zip.readUInt32LE(end) === 0x06054b50 && end + 22 + zip.readUInt16LE(end + 20) === zip.length) break;
      }
      if (end < Math.max(0, zip.length - 65_557)) throw new Error("MUSE-GATE-11 custody export is not a complete ZIP");
      const entries = zip.readUInt16LE(end + 10);
      let cursor = zip.readUInt32LE(end + 16);
      for (let index = 0; index < entries; index++) {
        if (zip.readUInt32LE(cursor) !== 0x02014b50) throw new Error("MUSE-GATE-11 invalid export directory");
        const method = zip.readUInt16LE(cursor + 10);
        const compressed = zip.readUInt32LE(cursor + 20);
        const nameLength = zip.readUInt16LE(cursor + 28);
        const extraLength = zip.readUInt16LE(cursor + 30);
        const commentLength = zip.readUInt16LE(cursor + 32);
        const local = zip.readUInt32LE(cursor + 42);
        const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
        if (name === "records/secret_custody.jsonl") {
          const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
          const wire = zip.subarray(start, start + compressed);
          if (method !== 0 && method !== 8) throw new Error("MUSE-GATE-11 unsupported export compression");
          const text = (method === 0 ? wire : inflateRawSync(wire)).toString("utf8");
          museGate11ExpectNoValues(text, secretValues);
          const rows = text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as { id: string; handle: string | null; body: string | null });
          const row = rows.find((candidate) => candidate.id === secretId);
          if (!row?.handle) throw new Error("MUSE-GATE-11 registered custody record has no exported handle");
          expect(row.body).toBeNull();
          return row.handle;
        }
        cursor += 46 + nameLength + extraLength + commentLength;
      }
      throw new Error("MUSE-GATE-11 export omitted custody rows");
    };
    const secretRefusal = async (work: Promise<unknown>, status: number, code: string): Promise<PublicHttpError> => {
      try { await work } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        if (error.reply.status !== status || error.error?.code !== code) {
          throw new Error(`MUSE-GATE-11 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error });
        }
        museGate11ExpectNoValues(error.reply.body, secretValues);
        const ref = error.error?.receiptRef;
        if (typeof ref !== "string" || !ref) throw new Error(`MUSE-GATE-11 ${stage}: refusal has no receiptRef`);
        const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: ref });
        if (!receipt || receipt.outcome === "ok") throw new Error(`MUSE-GATE-11 ${stage}: refusal call receipt is absent or ok`);
        expect(receipt.outcome.refused.code).toBe(code);
        return error;
      }
      throw new Error(`MUSE-GATE-11 ${stage}: expected HTTP ${status} ${code}, got success`);
    };
    const museGate11RegisterAndRead = async (
      name: string,
      valueBase64: string,
      bindings?: FacadeInput<"vault.secrets.register">["bindings"],
    ) => {
      const request: FacadeInput<"vault.secrets.register"> = {
        name, class: "cross-vault", rung: 0, device_only: false,
        value_base64: valueBase64,
        ...(bindings ? { bindings } : {}),
      };
      stage = `register ${name}`;
      const reply = await engine.client.call("vault.secrets.register", request);
      expect(reply.name).toBe(name);
      museGate11ExpectNoValues(reply, secretValues);
      // Second door: custody view, keyed by name rather than the register.
      const custody = await engine.client.call("vault.secrets.custody.get", {
        name,
      } satisfies FacadeInput<"vault.secrets.custody.get">);
      expect(custody.known).toBe(true);
      expect(custody.held_here).toBe(true);
      // Cross-vault values stay non-portable: custody does not leave here.
      expect(custody.portable).toBe(false);
      expect(custody.name).toBe(name);
      expect(custody.secret_id).toBe(reply.secret_id);
      expect(custody.generation).toBe(reply.rotation_generation);
      museGate11ExpectNoValues(custody, secretValues);
      // Third door: the handle card an agent reads before any use.
      stage = `resolve public custody handle for ${name}`;
      const handle = await custodyHandle(reply.secret_id);
      stage = `describe custody handle for ${name}`;
      const card = await sender.client.call("reveal.describe", {
        handle,
      } satisfies FacadeInput<"reveal.describe">);
      expect(card.handle.length).toBeGreaterThan(0);
      expect(card.status).toBe("active");
      museGate11ExpectNoValues(card, secretValues);
      return { reply, custody, card, handle: card.handle };
    };

    // Probe with no binding: no grant, refused at the custody door first.
    const probeName = `muse-gate11-probe-${secretHex(4)}`;
    const probe = await museGate11RegisterAndRead(probeName, probeSecretB64);
    stage = "unbound T0 self.use refusal";
    await secretRefusal(sender.client.call("self.use", {
      handle: probe.handle, operation: secretOperation,
    } satisfies FacadeInput<"self.use">), 403, "FORBIDDEN");
    expect(provider.seenFixtureCalls).toHaveLength(0);
    expect((await engine.client.call("vault.secrets.custody.get", { name: probeName })).held_here).toBe(true);

    // Wrong actor kind: a scoped agent cannot register a secret into owner
    // custody. Refusal reads back as no custody record under that name.
    const agentSecretName = `muse-gate11-agent-attempt-${secretHex(4)}`;
    const agentRegister = await sender.client.raw(
      "POST", "/v1/core/facade/vault.secrets.register", {
        name: agentSecretName, class: "cross-vault", rung: 0,
        device_only: false, value_base64: sharedSecretB64,
      } satisfies FacadeInput<"vault.secrets.register">);
    expect(agentRegister.status).toBeGreaterThanOrEqual(400);
    const agentRegisterError = museGate11WireError(agentRegister.body);
    expect(agentRegisterError.code.length).toBeGreaterThan(0);
    expect(agentRegisterError.message.length).toBeGreaterThan(0);
    museGate11ExpectNoValues(agentRegister.body, secretValues);
    const agentCustody = await engine.client.call("vault.secrets.custody.get", {
      name: agentSecretName,
    } satisfies FacadeInput<"vault.secrets.custody.get">);
    expect(agentCustody.known).toBe(false);

    // Grant the use: owner registers the shared secret with a T0 binding
    // for exactly the effector the door named above. The agent never
    // names a tier at use time.
    const sharedName = `muse-gate11-shared-${secretHex(4)}`;
    const shared = await museGate11RegisterAndRead(sharedName, sharedSecretB64, [{
      effector: learnedEffector, tier_ceiling: 0, scopes: ["read"],
    }]);
    expect(shared.reply.bindings.some((binding) => binding.effector === learnedEffector
      && binding.tier_ceiling === 0 && binding.scopes.includes("read"))).toBe(true);

    stage = "bound T0 self.use through scripted native mail";
    enqueueMailCheck("bound-use");
    const boundUse = await sender.client.call("self.use", {
      handle: shared.handle, operation: secretOperation,
    } satisfies FacadeInput<"self.use">);
    expect(boundUse.status).not.toBe("withheld");
    expect(boundUse.status).toBe("answered");
    expect(provider.seenFixtureCalls).toHaveLength(2);
    // The model-facing answer carries the result or failure, never the value
    // in raw or base64 form, and custody is still held here afterwards.
    museGate11ExpectNoValues(boundUse, secretValues);
    const custodyAfterUse = await engine.client.call("vault.secrets.custody.get", {
      name: sharedName,
    } satisfies FacadeInput<"vault.secrets.custody.get">);
    expect(custodyAfterUse.held_here).toBe(true);
    expect(custodyAfterUse.portable).toBe(false);

    // Cross-vault custody is T0-only: use is allowed at its door, but a T1
    // reveal is refused and no value enters the agent's context.
    stage = "cross-vault T0 secret cannot be revealed into context";
    await secretRefusal(sender.client.call("reveal", {
      handle: shared.handle, why: "check Gate11 shared secret in context",
    } satisfies FacadeInput<"reveal">), 400, "BAD_REQUEST");
    const revealCard = await sender.client.call("reveal.describe", { handle: shared.handle });
    expect(revealCard.reveal).toBe("refused");
    museGate11ExpectNoValues(revealCard, secretValues);

    // ------------------------------------------------------------------
    // P-GATE-030: a channel_send of private content must satisfy BOTH
    // gates, not either. The content is an owner-authored claim whose raw
    // sentinel the owner can read back; the send names it only by ref.
    // ------------------------------------------------------------------
    const claimScope = await ownerBaseClaimScope(engine.client, ownerRef);
    const projectRef = claimScope.scope_project_id;
    stage = "owner private-content claim and readback";
    const claimReceipt = await engine.client.call("vault.claims.upsert", {
      scope: claimScope, predicate: "profile.muse_gate11_private_note",
      subject_ref: ownerRef, value: privateSentinel,
      source: "user_stated", confidence: 1, occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(claimReceipt.receipt_ref);
    const claims = await engine.client.call("vault.claims.list", {
      subject_ref: ownerRef, predicate: "profile.muse_gate11_private_note", limit: 10,
    } satisfies FacadeInput<"vault.claims.list">);
    expect(claims.value.some((row) => row.value === privateSentinel)).toBe(true);
    const contentRef = claimReceipt.claim?.id ?? claimReceipt.claim_short_id;
    expect(contentRef.length).toBeGreaterThan(0);

    // Outbound channels come from their capability manifests, not the MCP
    // connector catalog. The schedule door has no delivery adapter.
    stage = "discover outbound send capability";
    const connectors = (await engine.client.request<{ connector: string; verbs: { kind: string }[] }[]>(
      "GET", "/v1/core/outbound/capabilities",
    )).body;
    const sendConnector = connectors.find((entry) => entry.connector === "email" && entry.verbs.some((verb) => verb.kind === "send"));
    if (!sendConnector) {
      throw new Error("MUSE-GATE-11 live outbound capabilities omitted email send");
    }
    const channel = sendConnector.connector;
    expect(channel.length).toBeGreaterThan(0);

    type MuseGate11SetupConnection = {
      id: string; secrets: { name: string; stored: boolean }[];
      permissions: { id: string; granted: boolean }[];
      check: { state: string }; ready: boolean;
    };
    type MuseGate11SetupReply = { setup: {
      pack_name: string; status: string; ready: boolean;
      connections: MuseGate11SetupConnection[];
    } };
    const museGate11MailConnection = (reply: MuseGate11SetupReply) => {
      const connection = reply.setup.connections.find((row) => row.id === "mail-server");
      if (!connection) throw new Error(`MUSE-GATE-11 ${stage}: native-mail setup has no mail-server connection`);
      return connection;
    };
    const museGate11ReadMailSetup = async () => (await engine.client.request<MuseGate11SetupReply>(
      "GET", "/v1/owner/packs/setup?pack=oneiron.native_mail",
    )).body;

    stage = "prepare native-mail built-in pack setup";
    await engine.client.request<MuseGate11SetupReply>(
      "POST", "/v1/owner/packs/setup/prepare", { pack: "oneiron.native_mail" },
    );
    const mailPrepared = await museGate11ReadMailSetup();
    expect(mailPrepared.setup.pack_name).toBe("oneiron.native_mail");
    expect(mailPrepared.setup.status).toBe("candidate");

    const mailCredential = `Bearer muse-gate11-mail-credential-${secretHex(16)}`;
    redactor.add(mailCredential, Buffer.from(mailCredential).toString("base64"));
    stage = "register native-mail server credential";
    const mailSecret = (await engine.client.request<{ secret_id: string; name: string }>(
      "POST", "/v1/owner/secrets/register", {
        name: "native_mail.authorization", class: "cross-vault", rung: 0,
        bindings: [{ effector: "connector:native_mail", tier_ceiling: 0, scopes: ["read"] }],
        value_base64: Buffer.from(mailCredential).toString("base64"),
      },
    )).body;
    museGate11ExpectNoValues(mailSecret, [mailCredential]);
    const mailCustody = await engine.client.call("vault.secrets.custody.get", { name: "native_mail.authorization" });
    expect(mailCustody.secret_id).toBe(mailSecret.secret_id);
    expect(mailCustody.held_here).toBe(true);
    expect(mailCustody.known).toBe(true);
    expect(mailCustody.portable).toBe(false);
    museGate11ExpectNoValues(mailCustody, [mailCredential]);

    stage = "pin native-mail credential to setup";
    await engine.client.request<MuseGate11SetupReply>(
      "POST", "/v1/owner/packs/setup/answer", { pack: "oneiron.native_mail",
        answer: { answer: "secret_stored", connection: "mail-server", secret: "native_mail.authorization" } },
    );
    const mailPinned = await museGate11ReadMailSetup();
    expect(museGate11MailConnection(mailPinned).secrets.find((row) => row.name === "native_mail.authorization")?.stored)
      .toBe(true);

    stage = "allow native-mail setup permissions";
    await engine.client.request<MuseGate11SetupReply>(
      "POST", "/v1/owner/packs/setup/answer", { pack: "oneiron.native_mail",
        answer: { answer: "allow", connection: "mail-server", permissions: ["identity", "inbound", "read", "send"] } },
    );
    const mailAllowed = museGate11MailConnection(await museGate11ReadMailSetup());
    expect(mailAllowed.permissions).toHaveLength(4);
    expect(mailAllowed.permissions.every((permission) => permission.granted)).toBe(true);

    stage = "verify native-mail connection and install built-in pack";
    // One connection check and four isolated read-only checks during qualification.
    for (const tag of ["mail-verify", "mail-probe-before", "mail-probe-first", "mail-probe-second", "mail-probe-after"]) {
      enqueueMailCheck(tag);
    }
    await engine.client.request<MuseGate11SetupReply>(
      "POST", "/v1/owner/packs/setup/verify", { pack: "oneiron.native_mail", connection: "mail-server" },
    );
    const mailVerified = await museGate11ReadMailSetup();
    expect(mailVerified.setup.ready).toBe(true);
    expect(mailVerified.setup.status).toBe("active");
    expect(museGate11MailConnection(mailVerified).ready).toBe(true);
    expect(museGate11MailConnection(mailVerified).check.state).toBe("verified");
    const installedMailPack = await engine.client.call("vault.packs.get", { name: "oneiron.native_mail" });
    expect(installedMailPack?.status).toBe("active");
    expect(provider.seenFixtureCalls).toHaveLength(12);

    // Actor ceilings are setup, not either consent Grant under test.
    stage = "set outbound actor ceilings and read policy back";
    const senderPolicy = await engine.client.call("vault.gate.policy.put", {
      manifest: policyManifest("e2e-muse-gate11-actors", "1", [
        { actor_class: "agent", actor_ref: sender.principalRef, ceiling: "auto" },
        { actor_class: "agent", actor_ref: noGrantAgent.principalRef, ceiling: "auto" },
      ]),
    });
    const senderPolicyReadback = await engine.client.call("vault.gate.policy.get", {
      manifest_ref: senderPolicy.manifest.manifest_ref,
    });
    expect(senderPolicyReadback.manifests[0]?.manifest.actor_ceilings).toEqual([
      { actor_class: "agent", actor_ref: sender.principalRef, ceiling: "auto" },
      { actor_class: "agent", actor_ref: noGrantAgent.principalRef, ceiling: "auto" },
    ]);

    const museGate11Send = (tag: string): FacadeInput<"connector.outbound.schedule"> => ({
      verb: "send", channel, target: recipientRef, content_ref: contentRef,
      idempotency_key: `muse-gate11-${tag}-once`,
      dedupe_key: `muse-gate11-${tag}`,
      trigger: "agent_immediate", trigger_ref: claimReceipt.receipt_ref,
    });
    type MuseGate11Client = (typeof sender)["client"];
    const museGate11CanAs = async (client: MuseGate11Client, tag: string) => {
      stage = `mixed send can ${tag}`;
      const answer = await client.call("can", {
        effect: { outbound_schedule: museGate11Send(tag) },
      } satisfies FacadeInput<"can">);
      museGate11ExpectNoValues(answer, [privateSentinel, ...secretValues]);
      return museGate11CanVerdict(answer);
    };
    const museGate11ScheduleAs = async (client: MuseGate11Client, tag: string) => {
      try {
        stage = `mixed send schedule ${tag}`;
        const receipt = await client.call(
          "connector.outbound.schedule", museGate11Send(tag));
        museGate11ExpectNoValues(receipt, [privateSentinel, ...secretValues]);
        if (!receipt.gate_decision_ref) throw new Error(`MUSE-GATE-11 ${stage}: schedule has no gate decision`);
        await engine.awaitReceipt(receipt.gate_decision_ref);
        return { kind: "receipt" as const, receipt };
      } catch (error) {
        if (error instanceof PublicHttpError) {
          if (error.reply.status === 400) throw error;
          const wire = museGate11WireError(error.reply.body);
          return {
            kind: "refused" as const, status: error.reply.status,
            code: wire.code, message: wire.message, suggestion: error.error?.suggestions?.[0] ?? "<none>",
          };
        }
        throw error;
      }
    };
    const museGate11GateAllows = (
      attempt: Awaited<ReturnType<typeof museGate11ScheduleAs>>,
    ): boolean => attempt.kind === "receipt"
      && attempt.receipt.gate_outcome === "allow";

    const museGate11Registry = async () => engine.client.call("vault.consent.registry", {
      limit: 1000,
    } satisfies FacadeInput<"vault.consent.registry">);
    const museGate11LiveGrantRefs = async (): Promise<string[]> =>
      (await museGate11Registry()).rows.map((row) => row.grant_ref).sort();
    type MuseGate11Domain = FacadeResult<"vault.consent.registry">["rows"][number]["domain"];
    const museGate11RegistryRow = async (grantRef: string, domain: MuseGate11Domain) => {
      const registry = await museGate11Registry();
      const row = registry.rows.find((candidate) => candidate.grant_ref === grantRef);
      if (!row) throw new Error("Standing grant is absent from the consent registry");
      expect(row.domain).toBe(domain);
      expect(row.class).toBe("channel_send");
      return row;
    };

    const actionBound: FacadeInput<"vault.consent.create_standing_grant">["bound"] = {
      actor: sender.principalRef, class: "channel_send",
      envelope: { project: projectRef, audience: [recipientRef] },
    };
    const disclosureBound: FacadeInput<"vault.consent.create_standing_grant">["bound"] = {
      audience: [recipientRef], class: "channel_send",
      envelope: { selectors: [contentRef] },
    };

    // Wrong actor kind, consent side: an agent's self-grant attempt is
    // refused in the standard envelope and leaves the registry unchanged.
    const refsBeforeSelfGrant = await museGate11LiveGrantRefs();
    stage = "agent self-grant refusal and registry readback";
    const selfGrant = await sender.client.raw(
      "POST", "/v1/core/facade/vault.consent.create_standing_grant", {
        bound: actionBound,
      } satisfies FacadeInput<"vault.consent.create_standing_grant">);
    expect(selfGrant.status).toBeGreaterThanOrEqual(400);
    const selfGrantError = museGate11WireError(selfGrant.body);
    expect(selfGrantError.code.length).toBeGreaterThan(0);
    expect(selfGrantError.message.length).toBeGreaterThan(0);
    expect(await museGate11LiveGrantRefs()).toEqual(refsBeforeSelfGrant);

    // Proof order 1: no grant, refused for both agents.
    const noGrantSenderVerdict = await museGate11CanAs(sender.client, "no-grant-sender");
    expect(noGrantSenderVerdict).not.toBe("allow");
    const noGrantAgentVerdict = await museGate11CanAs(noGrantAgent.client, "no-grant-agent");
    expect(noGrantAgentVerdict).not.toBe("allow");
    const noGrantSchedule = await museGate11ScheduleAs(sender.client, "no-grant-schedule");
    expect(museGate11GateAllows(noGrantSchedule)).toBe(false);

    // Proof order 2a: action grant alone is not either-gate enough.
    stage = "create action-only standing grant";
    const actionReceipt1 = await engine.client.call("vault.consent.create_standing_grant", {
      bound: actionBound,
    } satisfies FacadeInput<"vault.consent.create_standing_grant">);
    const actionGrant1 = museGate11GrantRef(actionReceipt1);
    await museGate11RegistryRow(actionGrant1, "action");
    const actionOnlyVerdict = await museGate11CanAs(sender.client, "action-only");
    expect(actionOnlyVerdict).not.toBe("allow");
    const actionOnlySchedule = await museGate11ScheduleAs(sender.client, "action-only");
    expect(museGate11GateAllows(actionOnlySchedule)).toBe(false);

    // Remove it before testing disclosure alone; the live registry is the
    // read-back that the action grant is gone.
    await engine.client.call("vault.consent.revoke", {
      grant: actionGrant1,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect((await museGate11LiveGrantRefs()).includes(actionGrant1)).toBe(false);

    // Proof order 2b: disclosure grant alone is not either-gate enough.
    stage = "create disclosure-only standing grant";
    const disclosureReceipt = await engine.client.call("vault.consent.create_standing_grant", {
      bound: disclosureBound,
    } satisfies FacadeInput<"vault.consent.create_standing_grant">);
    const disclosureGrant = museGate11GrantRef(disclosureReceipt);
    await museGate11RegistryRow(disclosureGrant, "disclosure");
    const disclosureOnlyVerdict = await museGate11CanAs(sender.client, "disclosure-only");
    expect(disclosureOnlyVerdict).not.toBe("allow");
    const disclosureOnlySchedule = await museGate11ScheduleAs(sender.client, "disclosure-only");
    expect(museGate11GateAllows(disclosureOnlySchedule)).toBe(false);

    // Proof order 2c: both disjoint grants live; the same mixed send passes
    // both checks for the bound actor and stays refused for the other agent.
    stage = "create second action standing grant";
    const actionReceipt2 = await engine.client.call("vault.consent.create_standing_grant", {
      bound: actionBound,
    } satisfies FacadeInput<"vault.consent.create_standing_grant">);
    const actionGrant2 = museGate11GrantRef(actionReceipt2);
    expect(actionGrant2).not.toBe(disclosureGrant);
    await museGate11RegistryRow(actionGrant2, "action");
    await museGate11RegistryRow(disclosureGrant, "disclosure");
    const bothVerdict = await museGate11CanAs(sender.client, "both-grants");
    expect(bothVerdict).toBe("allow");
    const bothNoGrantVerdict = await museGate11CanAs(noGrantAgent.client, "both-grants-other-agent");
    expect(bothNoGrantVerdict).not.toBe("allow");
    const bothSchedule = await museGate11ScheduleAs(sender.client, "both-grants");
    expect(bothSchedule.kind).toBe("receipt");
    expect(museGate11GateAllows(bothSchedule)).toBe(true);
    if (bothSchedule.kind !== "receipt") {
      throw new Error(`Both-grant schedule was refused: status=${bothSchedule.status} code=${bothSchedule.code} message=${bothSchedule.message} suggestion=${bothSchedule.suggestion}`);
    }
    // Covered by live standing grants: reuse inside the bound needs no
    // fresh approval digest. Delivery itself is not asserted; no
    // external channel transport exists in this fixture.
    expect(bothSchedule.receipt.approval_digest ?? null).toBeNull();
    const bothNoGrantSchedule = await museGate11ScheduleAs(noGrantAgent.client, "both-grants-other-agent");
    expect(museGate11GateAllows(bothNoGrantSchedule)).toBe(false);

    await engine.artifacts.json("muse-gate11-attempts.json", {
      secretEffector: learnedEffector,
      verdicts: {
        noGrantSenderVerdict, noGrantAgentVerdict, actionOnlyVerdict,
        disclosureOnlyVerdict, bothVerdict, bothNoGrantVerdict,
      },
      schedules: {
        noGrantSchedule, actionOnlySchedule, disclosureOnlySchedule,
        bothSchedule, bothNoGrantSchedule,
      },
    });

    // Full door, part 4: restart, then read every live outcome again.
    stage = "restart custody and standing-grant readback";
    await engine.restart();
    const custodyAfterRestart = await engine.client.call("vault.secrets.custody.get", {
      name: sharedName,
    } satisfies FacadeInput<"vault.secrets.custody.get">);
    expect(custodyAfterRestart.known).toBe(true);
    expect(custodyAfterRestart.held_here).toBe(true);
    expect(custodyAfterRestart.portable).toBe(false);
    const cardAfterRestart = await sender.client.call("reveal.describe", {
      handle: shared.handle,
    } satisfies FacadeInput<"reveal.describe">);
    expect(cardAfterRestart.status).toBe("active");
    museGate11ExpectNoValues(cardAfterRestart, secretValues);
    stage = "T0 self.use after restart";
    enqueueMailCheck("restart-use");
    const useAfterRestart = await sender.client.call("self.use", {
      handle: shared.handle, operation: secretOperation,
    } satisfies FacadeInput<"self.use">);
    expect(useAfterRestart.status).not.toBe("withheld");
    expect(useAfterRestart.status).toBe("answered");
    expect(provider.seenFixtureCalls).toHaveLength(14);
    museGate11ExpectNoValues(useAfterRestart, secretValues);
    await museGate11RegistryRow(actionGrant2, "action");
    await museGate11RegistryRow(disclosureGrant, "disclosure");
    const claimsAfterRestart = await engine.client.call("vault.claims.list", {
      subject_ref: ownerRef, predicate: "profile.muse_gate11_private_note", limit: 10,
    } satisfies FacadeInput<"vault.claims.list">);
    expect(claimsAfterRestart.value.some((row) => row.value === privateSentinel)).toBe(true);
    expect(await museGate11CanAs(sender.client, "after-restart")).toBe("allow");

    // Proof order 3: the sender loses the action grant mid-flow and is
    // refused at its next use, even though the disclosure grant remains.
    await engine.client.call("vault.consent.revoke", {
      grant: actionGrant2,
    } satisfies FacadeInput<"vault.consent.revoke">);
    expect((await museGate11LiveGrantRefs()).includes(actionGrant2)).toBe(false);
    await museGate11RegistryRow(disclosureGrant, "disclosure");
    const afterActionRevokeVerdict = await museGate11CanAs(sender.client, "after-action-revoke");
    expect(afterActionRevokeVerdict).not.toBe("allow");
    const afterActionRevokeSchedule = await museGate11ScheduleAs(sender.client, "after-action-revoke");
    expect(museGate11GateAllows(afterActionRevokeSchedule)).toBe(false);

    // Secret twin of losing authority: owner revokes the shared secret;
    // the next bound use is refused before the provider sees a request.
    stage = "owner secret revoke and custody readback";
    const secretRevoked = await engine.client.call("vault.secrets.revoke", {
      name: sharedName,
    } satisfies FacadeInput<"vault.secrets.revoke">);
    museGate11ExpectNoValues(secretRevoked, secretValues);
    const custodyAfterRevoke = await engine.client.call("vault.secrets.custody.get", {
      name: sharedName,
    } satisfies FacadeInput<"vault.secrets.custody.get">);
    stage = "revoked secret refuses next T0 use";
    const useAfterRevoke = await secretRefusal(sender.client.call("self.use", {
      handle: shared.handle, operation: secretOperation,
    } satisfies FacadeInput<"self.use">), 400, "BAD_REQUEST");
    expect(provider.seenFixtureCalls).toHaveLength(14);
    museGate11ExpectNoValues(useAfterRevoke.reply.body, secretValues);

    await engine.artifacts.json("muse-gate11-final.json", {
      probeHandle: probe.handle, sharedHandle: shared.handle,
      contentRef, channel, afterActionRevokeVerdict,
      afterActionRevokeSchedule,
      custodyAfterRevoke: {
        secret_id: custodyAfterRevoke.secret_id, known: custodyAfterRevoke.known,
        held_here: custodyAfterRevoke.held_here, portable: custodyAfterRevoke.portable,
        generation: custodyAfterRevoke.generation, status: custodyAfterRevoke.status ?? null,
      },
      useAfterRevoke: { status: useAfterRevoke.reply.status, code: useAfterRevoke.error?.code },
    });
  } catch (error) {
    const detail = error instanceof PublicHttpError
      ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
      : error instanceof Error ? error.message : String(error);
    primaryFailed = true;
    if (stage.startsWith("mixed send")) {
      primary = new Error(
        `MUSE-GATE-11 ENGINE DEFECT 2026-11-11: P-GATE-030 / DEC-0006 invariant 4 needs action AND disclosure; outbound composes only action (FIX-LIST 2802, still HELD); standing action bound also uses a different envelope from the outbound requirement; ${stage}: ${detail}`,
        { cause: error },
      );
    } else {
      primary = new Error(`MUSE-GATE-11 ${stage}: ${detail}`, { cause: error });
    }
  } finally {
    const cleanup = await Promise.allSettled([engine.close(), provider.close()]);
    const failures = cleanup.filter((row): row is PromiseRejectedResult => row.status === "rejected").map((row) => row.reason);
    if (failures.length > 0) throw new AggregateError(primaryFailed ? [primary, ...failures] : failures,
      `${primaryFailed ? String(primary) : "MUSE-GATE-11 cleanup"}; cleanup: ${failures.map(String).join("; ")}`);
    if (primaryFailed) throw primary;
  }
});
