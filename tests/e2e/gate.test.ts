import { afterAll, test } from "bun:test";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, expect, LIMITS } from "./support/run.ts";

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
// Current owner_confirm.preview and records.erase_confirm are real, but create no bypass.
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
