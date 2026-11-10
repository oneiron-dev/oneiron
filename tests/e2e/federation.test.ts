import { afterAll, expect, test } from "bun:test";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { encode } from "@msgpack/msgpack";
import { blake3 } from "@noble/hashes/blake3";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic, type PairedActor } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError, WsClient, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

// Binding readback: main e79eb76df3e406c22ea49a04af0f5144d3aff119.
// Fixtures: federation-canon-scenarios, fixtures/federation/scenarios.json.
// Source pins and independent expected facts are in the hash-checked fixture.
//
// Written cases are partial subsets (Engine ruling E2E-PARTIAL = A): each test
// name states exactly the promise it proves, and the comment above it names what
// of the planned title stays unproved and the public door that is missing.
// Unwritten cases stay suite.todo (BLOCKED) with the real missing door.
// No generic facade casts, batch/structural authority writes, private signing,
// fake vaults, or internal admission/replay calls stand in for missing doors.

// FEDERATION-01 — Member and admin powers should work.
// OF-150/158/157/287/331; ARCH-0043#shared-vault-authority.
interface Fed01Fixture {
  setup: { principals: { label: string; role: string }[] };
  cases: { id: string; inputs: {
    sharedPreset?: Facade.ShapePreset;
    memberChangeSequence?: string[];
    delegate?: { scope: string; expires: boolean; onwardDelegation: boolean };
  } }[];
}

async function fed01Entity(client: PublicHttpClient, entityRef: string): Promise<Facade.EntityView> {
  const result = await client.call("vault.get", { entity_ref: entityRef });
  if (!result.value) throw new Error(`Public entity missing: ${entityRef}`);
  return result.value;
}

async function fed01Refused(
  owner: PublicHttpClient, actorRef: string, act: () => Promise<unknown>,
  status: number, code: string, hasReceipt = true,
): Promise<void> {
  let failure: unknown;
  try { await act(); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error("Expected a public HTTP refusal");
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  if (hasReceipt) {
    const receiptRef = failure.error?.receiptRef;
    if (typeof receiptRef !== "string") throw new Error("Authenticated refusal has no receiptRef");
    expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
    const receipt = await owner.call("vault.receipts.get", { receipt_ref: receiptRef });
    if (!receipt) throw new Error("Refusal receipt is not publicly readable by the Owner");
    expect(receipt.receipt_ref).toBe(receiptRef);
    expect(receipt.actor_ref).toBe(actorRef);
    expect(receipt.actor_class).toBe("human");
    expect(receipt.outcome).toEqual({ refused: { code } });
  }
}

async function fed01Role(
  client: PublicHttpClient, vaultId: string, member: string, role: Facade.FederationGrantRole,
): Promise<Facade.FederationMemberGrant> {
  const projection = await client.call("vault.members.projection", { vault_id: vaultId, member });
  expect(projection.member_ref).toBe(member);
  const grant = projection.grants.find(row => row.active && row.role === role);
  if (!grant) throw new Error(`No live ${role} grant in the public member projection`);
  expect(grant.vault_id).toBe(vaultId);
  expect(grant.member_ref).toBe(member);
  return grant;
}

async function fed01Diagnose<T>(label: string, act: () => Promise<T>): Promise<T> {
  try {
    return await act();
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    const detail = error.error;
    const receiptRef = detail?.receiptRef;
    throw new Error(
      `FEDERATION-01 ENGINE DEFECT 2026-11-10: accepted Admin has no writable authority binding; ${label}: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} receiptRef=${typeof receiptRef === "string" ? receiptRef : "<none>"} header=${error.reply.headers.get("x-oneiron-receipt-ref") ?? "<none>"} error=${JSON.stringify(detail) ?? "<none>"} body=${JSON.stringify(error.reply.body) ?? "<none>"}`,
      { cause: error },
    );
  }
}

/* Promise: Admin membership changes respect Owner authority and revoke removed access; Delegates cannot delegate onward.
 * Doors: evidence-backed people + CLI/SDK pairing; shape; members; shared.receipt; receipts.get; restart.
 * Unproved: document-only Delegate expiry, all named powers, other role/content ceilings, relationship authority and personal-vault isolation.
 */
suite.test(test, "FEDERATION-01", "An Admin can invite, change and remove non-Owners, cannot promote itself to Owner, removal invalidates the member's next authenticated call, and a Delegate cannot delegate onward.", async () => {
  const data = await (await loadFixtures()).readJson<Fed01Fixture>("federation-canon-scenarios");
  const scenario = data.cases.find(row => row.id === "FEDERATION-01");
  if (!scenario || scenario.inputs.sharedPreset !== "org") throw new Error("Missing org membership fixture");
  if (scenario.inputs.delegate?.onwardDelegation !== false) throw new Error("Missing no-onward-delegation oracle");
  const label = (role: string): string => {
    const person = data.setup.principals.find(row => row.role === role);
    if (!person) throw new Error(`Missing fixture principal ${role}`);
    return person.label;
  };
  const names = [label("admin"), label("member"), label("delegate")];
  const engine = await EngineFixture.start({ id: "FEDERATION-01", profile, peers: 0 });
  try {
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const vaultId = "41"; // Public shared setup identifier, not a seeded record.
    const occurred = 1769947200; // Evidence event time; never the engine's clock.
    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    expect((await fed01Entity(owner, conversation.id)).kind).toBe("CONVERSATION");
    const witnessed = await owner.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: occurred,
      messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
        content: `These are distinct people: ${names.join(", ")}.` }],
    });
    const evidence = await fed01Entity(owner, witnessed.turn_short_id);
    expect(evidence.kind).toBe("TURN");
    const people: string[] = [];
    for (const name of names) {
      const created = await owner.call("vault.people.create", {
        identity: { name }, identity_evidence_refs: [evidence.id_hex], occurred_at: occurred,
      });
      const person = await fed01Entity(owner, created.person.entity_ref);
      expect(person.kind).toBe("PERSON");
      expect(person.id_hex).toBe(created.person.id_hex);
      expect(person.id_hex).not.toBe(ownerRef);
      people.push(person.id_hex);
    }
    expect(new Set(people).size).toBe(3);
    const [adminRef, memberRef, delegateRef] = [people[0]!, people[1]!, people[2]!];
    const admin = await engine.pairActor({ principalRef: adminRef, actorClass: "human" });
    const member = await engine.pairActor({ principalRef: memberRef, actorClass: "human" });
    const delegate = await engine.pairActor({ principalRef: delegateRef, actorClass: "human" });
    for (const actor of [admin, member, delegate]) {
      expect((await actor.client.call("self.actor", {})).actor_ref).toBe(actor.principalRef);
    }

    const plan = await owner.call("vault.shape.plan", { preset: {
      preset: scenario.inputs.sharedPreset, vault_id: vaultId, members: [{ member: adminRef, role: "admin" }],
    } });
    const approve = plan.items.filter(item => item.change === "create" &&
      (item.target.kind === "shared" || item.target.kind === "member")).map(item => item.seq);
    const applied = await owner.call("vault.shape.apply", { plan, approve });
    const shared = applied.items.find(item => item.item.target.kind === "shared");
    if (!shared || shared.state.state !== "landed") throw new Error("Shared vault setup did not land");
    expect(shared.state.receipt).toBe(vaultId);
    await fed01Role(owner, vaultId, ownerRef, "owner");
    const adminInvitation = (await admin.client.call("vault.members.invitations", { vault_id: vaultId }))
      .find(row => row.invitee === adminRef);
    if (!adminInvitation) throw new Error("Founding Admin invitation is missing");
    expect(adminInvitation.state).toBe("pending");
    expect(adminInvitation.role).toBe("admin");
    expect(adminInvitation.founding).toBe(true);
    const adminAccepted = await admin.client.call("vault.members.accept", {
      vault_id: vaultId, invitation: adminInvitation.id,
    });
    expect(adminAccepted.change).toEqual({ invitation_accepted: {
      invitation: adminInvitation.id, member: adminRef, role: "admin",
    } });
    const adminGrant = await fed01Role(owner, vaultId, adminRef, "admin");

    const invited = await fed01Diagnose("admin vault.members.add", () => admin.client.call("vault.members.add", {
      vault_id: vaultId, member: memberRef, role: "member",
    }));
    expect(invited.actor).toBe(adminRef);
    expect(invited.vault_id).toBe(vaultId);
    const invitation = (await member.client.call("vault.members.invitations", { vault_id: vaultId }))
      .find(row => row.invitee === memberRef);
    if (!invitation) throw new Error("Admin's invitation is missing at the invitee's door");
    expect(invitation.inviter).toBe(adminRef);
    expect(invitation.role).toBe("member");
    expect(invitation.state).toBe("pending");
    expect(invitation.founding).toBe(false);
    expect(invited.change).toEqual({ member_invited: {
      invitation: invitation.id, member: memberRef, role: "member", expires_at: invitation.expires_at,
    } });
    expect((await owner.call("vault.shared.receipt", { receipt_id: invited.id })).change).toEqual(invited.change);
    const accepted = await member.client.call("vault.members.accept", {
      vault_id: vaultId, invitation: invitation.id,
    });
    expect(accepted.change).toEqual({ invitation_accepted: {
      invitation: invitation.id, member: memberRef, role: "member",
    } });
    await fed01Role(owner, vaultId, memberRef, "member");

    await fed01Refused(owner, memberRef, () => member.client.call("vault.members.change", {
      vault_id: vaultId, member: memberRef, role: "admin",
    }), 403, "FORBIDDEN");
    await fed01Role(owner, vaultId, memberRef, "member");
    await fed01Refused(owner, adminRef, () => admin.client.call("vault.members.change", {
      vault_id: vaultId, member: adminRef, role: "owner",
    }), 400, "BAD_REQUEST");
    await fed01Role(owner, vaultId, adminRef, "admin");
    const unchangedAdmin = await owner.call("vault.members.projection", { vault_id: vaultId, member: adminRef });
    expect(unchangedAdmin.grants.some(row => row.active && row.role === "owner")).toBe(false);
    await fed01Refused(owner, adminRef, () => admin.client.call("vault.members.remove", {
      vault_id: vaultId, member: ownerRef,
    }), 400, "BAD_REQUEST");
    await fed01Role(owner, vaultId, ownerRef, "owner");

    // This read-only grant proves one-hop delegation, not the fixture's document-only/expiry journey.
    const delegateScope: Facade.Scope = {
      worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
      audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] }, sensitivity: { kind: "all" },
    };
    const expiresAt = accepted.completed_at + 3600; // One-hour input anchored to a public server receipt.
    const delegated = await fed01Diagnose("admin vault.members.delegate", () => admin.client.call("vault.members.delegate", {
      parent_grant: adminGrant.grant_ref, member_ref: delegateRef, authority_scope: delegateScope, expires_at: expiresAt,
    }));
    const delegateGrant = await fed01Role(owner, vaultId, delegateRef, "delegate");
    expect(delegateGrant.grant_ref).toBe(delegated.grant_ref);
    expect(delegateGrant.delegated_by).toBe(adminRef);
    expect(delegateGrant.expires_at).toBe(expiresAt);
    // Input `sensitivity: {kind:"all"}` is stored as its canonical top, at_most restricted (oneiron-authority federation/scope.rs:182-231).
    expect(delegateGrant.authority_scope).toEqual({
      ...delegateScope,
      sensitivity: { kind: "at_most", value: "restricted" },
    });
    await fed01Refused(owner, delegateRef, () => delegate.client.call("vault.members.delegate", {
      parent_grant: delegateGrant.grant_ref, member_ref: memberRef, authority_scope: delegateScope, expires_at: expiresAt,
    }), 400, "BAD_REQUEST");
    const afterOnward = await owner.call("vault.members.projection", { vault_id: vaultId, member: memberRef });
    expect(afterOnward.grants.some(row => row.active && row.delegated_by === delegateRef)).toBe(false);

    const changed = await fed01Diagnose("admin vault.members.change", () => admin.client.call("vault.members.change", {
      vault_id: vaultId, member: memberRef, role: "viewer",
    }));
    expect(changed.change).toEqual({ member_role_changed: { member: memberRef, from: "member", to: "viewer" } });
    expect(changed.revoked_slips.length).toBeGreaterThan(0);
    await fed01Role(owner, vaultId, memberRef, "viewer");
    expect((await owner.call("vault.shared.receipt", { receipt_id: changed.id })).change).toEqual(changed.change);
    await fed01Refused(owner, memberRef, () => member.client.call("self.actor", {}), 401, "UNAUTHORIZED", false);
    // A new credential is proven live BEFORE removal, so the next refusal is not the earlier downgrade.
    const viewer = await engine.pairActor({ principalRef: memberRef, actorClass: "human", scope: ["core:read"] });
    await fed01Role(viewer.client, vaultId, memberRef, "viewer");
    const removed = await fed01Diagnose("admin vault.members.remove", () => admin.client.call("vault.members.remove", { vault_id: vaultId, member: memberRef }));
    await fed01Refused(owner, memberRef, () => viewer.client.call("vault.members.projection", {
      vault_id: vaultId, member: memberRef,
    }), 401, "UNAUTHORIZED", false);
    expect(removed.change).toEqual({ member_removed: { member: memberRef } });
    expect(removed.grants.length).toBeGreaterThan(0);
    expect(removed.revoked_slips.length).toBeGreaterThan(0);
    const removalReceipt = await owner.call("vault.shared.receipt", { receipt_id: removed.id });
    expect(removalReceipt.id).toBe(removed.id);
    expect(removalReceipt.vault_id).toBe(vaultId);
    expect(removalReceipt.actor).toBe(adminRef);
    expect(removalReceipt.change).toEqual(removed.change);
    expect(removalReceipt.grants).toEqual(removed.grants);
    expect(removalReceipt.revoked_slips).toEqual(removed.revoked_slips);
    const afterRemoval = await owner.call("vault.members.projection", { vault_id: vaultId, member: memberRef });
    expect(afterRemoval.grants.filter(row => row.active)).toHaveLength(0);

    await engine.restart();
    await fed01Refused(owner, memberRef, () => viewer.client.call("vault.members.projection", {
      vault_id: vaultId, member: memberRef,
    }), 401, "UNAUTHORIZED", false);
    const persistedReceipt = await owner.call("vault.shared.receipt", { receipt_id: removed.id });
    expect(persistedReceipt.id).toBe(removalReceipt.id);
    expect(persistedReceipt.change).toEqual(removalReceipt.change);
    expect(persistedReceipt.grants).toEqual(removalReceipt.grants);
    expect(persistedReceipt.revoked_slips).toEqual(removalReceipt.revoked_slips);
    const persisted = await owner.call("vault.members.projection", { vault_id: vaultId, member: memberRef });
    expect(persisted.grants.filter(row => row.active)).toHaveLength(0);
    await fed01Role(owner, vaultId, adminRef, "admin");
    expect(await fed01Role(owner, vaultId, delegateRef, "delegate")).toEqual(delegateGrant);
  } finally {
    await engine.close();
  }
});

// FEDERATION-02 — Owner veto window should work.
// OF-163; ARCH-0043#shared-vault-authority; identity#cloud-agent-recovery.
interface Fed02CasesFixture {
  readonly cases: readonly {
    readonly id: string;
    readonly inputs: { readonly fixtureVetoWaitSeconds: number; readonly acts: readonly string[] };
    readonly expected: { readonly defaultVetoWaitSeconds: number; readonly defaultActs: readonly string[] };
  }[];
}

async function fed02Refused(
  reader: PublicHttpClient, actorRef: string, act: () => Promise<unknown>,
  status: number, code: string,
): Promise<void> {
  let failure: unknown;
  try { await act(); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error("Expected a public HTTP refusal");
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  const receiptRef = failure.error?.receiptRef;
  if (typeof receiptRef !== "string" || !receiptRef.startsWith("call:")) {
    throw new Error("Authenticated refusal has no call receiptRef");
  }
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await reader.call("vault.receipts.get", { receipt_ref: receiptRef });
  if (!receipt) throw new Error("Refusal receipt is not publicly readable");
  expect(receipt.receipt_ref).toBe(receiptRef);
  expect(receipt.actor_ref).toBe(actorRef);
  expect(receipt.actor_class).toBe("human");
  expect(receipt.outcome).toEqual({ refused: { code } });
}

async function fed02Person(engine: EngineFixture, evidence: string, occurred: number, name: string): Promise<string> {
  const created = await engine.client.call("vault.people.create", {
    identity: { name },
    identity_evidence_refs: [evidence],
    occurred_at: occurred,
  });
  expect(created.person.id_hex).not.toBe(engine.pairedActor.principalRef);
  const read = await engine.client.call("vault.get", { entity_ref: created.person.entity_ref });
  if (!read.value || read.value.kind !== "PERSON") throw new Error(`person ${name} has no PERSON readback`);
  return created.person.id_hex;
}

async function fed02Accept(actor: PairedActor, vaultId: string, role: "owner" | "admin"): Promise<FacadeResult<"vault.members.accept">> {
  const invitations = await actor.client.call("vault.members.invitations", { vault_id: vaultId });
  const invitation = invitations.find(row => row.invitee === actor.principalRef);
  if (!invitation) throw new Error(`no invitation for ${actor.principalRef}`);
  expect(invitation.state).toBe("pending");
  expect(invitation.role).toBe(role);
  expect(invitation.vault_id).toBe(vaultId);
  expect(invitation.founding).toBe(true);
  const receipt = await actor.client.call("vault.members.accept", {
    vault_id: vaultId,
    invitation: invitation.id,
  });
  expect(receipt.vault_id).toBe(vaultId);
  expect(receipt.actor).toBe(actor.principalRef);
  expect(receipt.revoked_slips).toEqual([]);
  if (!("invitation_accepted" in receipt.change)) throw new Error("acceptance receipt names no invitation_accepted change");
  expect(receipt.change.invitation_accepted.invitation).toBe(invitation.id);
  expect(receipt.change.invitation_accepted.member).toBe(actor.principalRef);
  expect(receipt.change.invitation_accepted.role).toBe(role);
  const projection = await actor.client.call("vault.members.projection", {
    vault_id: vaultId,
    member: actor.principalRef,
  });
  expect(projection.member_ref).toBe(actor.principalRef);
  const grant = projection.grants.find(row => row.role === role && row.active);
  if (!grant) throw new Error(`accepted ${role} has no active grant in projection`);
  expect(grant.member_ref).toBe(actor.principalRef);
  expect(grant.vault_id).toBe(vaultId);
  return receipt;
}

/* FEDERATION-02 — decision: WRITTEN (partial).
 * Promise: two live Owners jointly configure a veto policy, an Owner objection survives restart, another Owner cannot clear it, and an Admin cannot object.
 * Doors: conversations.create, witness, get, people.create, self.actor, shape.plan/apply/read, members.invitations/accept/projection, shared.policy.get/propose/answer/change/changes, shared.propose_delete/object/withdraw_objection/execute/started/deletion/receipt, shared.owner_change_wait.get, receipts.get, restart.
 * Unproved: transfer/remove/erase veto journeys and the four-act 604800 default (transfer/remove ship at wait 0 with no veto; needs an engine ruling or fix, no new door).
 * Unproved: a public elapsed-maturity observation for the held act (matured only lists persisted notices; needs an Owner-grant act-status read such as vault.shared.act.get).
 * Unproved: former/dead third-Owner release (members.remove refuses Owners; needs a public person-liveness revocation verb behind Owner membership).
 * Unproved: last-Owner successor/self-removal, remove-Owner export_first true/false, and the co-Owner export receipt (needs separate destructive fixtures plus a public Owner-grant export-receipt read).
 */
suite.test(test, "FEDERATION-02", "Two live Owners jointly configure a veto policy, an Owner objection survives restart, another Owner cannot clear it, and an Admin cannot object", async () => {
  const fixture = await (await loadFixtures()).readJson<Fed02CasesFixture>("federation-canon-scenarios");
  const scenario = fixture.cases.find(row => row.id === "FEDERATION-02");
  if (!scenario) throw new Error("federation-canon-scenarios has no FEDERATION-02 row");
  // The engine clock is real whole seconds (store_clock.rs:29-35); a 2 s window can close between
  // the start and the co-Owner's objection. 31 s outlasts the 30 s case, and no step needs maturity.
  const waitSecs = Math.max(scenario.inputs.fixtureVetoWaitSeconds, 31);
  const defaultWaitSecs = scenario.expected.defaultVetoWaitSeconds;
  expect(scenario.inputs.acts).toContain("delete_vault");
  expect(scenario.expected.defaultActs).toContain("delete_vault");
  const engine = await EngineFixture.start({ id: "FEDERATION-02", profile, peers: 0 });
  try {
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const vaultId = "42";
    const occurred = 1769947200;
    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    const conversationRead = await owner.call("vault.get", { entity_ref: conversation.id });
    if (!conversationRead.value) throw new Error("conversation has no readback");
    const witnessed = await owner.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: occurred,
      messages: [{
        author: "user", message_type: "text", is_visible: true, order: 0,
        content: "These are distinct people: owner-b and admin-person.",
      }],
    });
    const evidenceRead = await owner.call("vault.get", { entity_ref: witnessed.turn_short_id });
    const evidenceValue = evidenceRead.value;
    if (!evidenceValue || evidenceValue.kind !== "TURN") throw new Error("identity evidence has no TURN readback");
    const evidence = evidenceValue.id_hex;
    const coOwnerRef = await fed02Person(engine, evidence, occurred, "owner-b");
    const adminRef = await fed02Person(engine, evidence, occurred, "admin-person");
    const coOwner = await engine.pairActor({ principalRef: coOwnerRef, actorClass: "human" });
    const admin = await engine.pairActor({ principalRef: adminRef, actorClass: "human" });
    expect((await coOwner.client.call("self.actor", {})).actor_ref).toBe(coOwnerRef);
    expect((await admin.client.call("self.actor", {})).actor_ref).toBe(adminRef);
    const plan = await owner.call("vault.shape.plan", {
      preset: { preset: "org", vault_id: vaultId, members: [{ member: coOwnerRef, role: "owner" }, { member: adminRef, role: "admin" }] },
    });
    const approve = plan.items
      .filter(item => {
        if (item.change !== "create") return false;
        if (item.target.kind === "shared") return true;
        if (item.target.kind === "member") return item.target.member !== ownerRef;
        return false;
      })
      .map(item => item.seq);
    const applied = await owner.call("vault.shape.apply", { plan, approve });
    const sharedItem = applied.items.find(entry => entry.item.target.kind === "shared");
    if (!sharedItem) throw new Error("shape apply landed no shared item");
    if (sharedItem.state.state !== "landed") throw new Error(`shared item did not land: ${sharedItem.state.state}`);
    expect(sharedItem.state.receipt).toBe(vaultId);
    const memberItems = applied.items.filter(entry => entry.item.change === "create" && entry.item.target.kind === "member");
    for (const entry of memberItems) {
      const target = entry.item.target;
      if (target.kind !== "member") throw new Error("member item lost its target");
      if (target.member === ownerRef) {
        if (entry.state.state === "refused" || entry.state.state === "no_door") {
          throw new Error("creator member row was refused");
        }
        continue;
      }
      if (entry.state.state !== "landed") throw new Error(`founding member item did not land: ${entry.state.state}`);
      expect(entry.state.receipt).toBe("founding member");
    }
    const founded = memberItems
      .filter(entry => {
        const target = entry.item.target;
        return target.kind === "member" && target.member !== ownerRef;
      })
      .map(entry => {
        const target = entry.item.target;
        if (target.kind !== "member") throw new Error("member item lost its target");
        return target.member;
      })
      .sort();
    expect(founded).toEqual([adminRef, coOwnerRef].sort());
    for (const entry of applied.items) {
      expect(entry.state.state).not.toBe("refused");
      expect(entry.state.state).not.toBe("no_door");
    }
    const shape = await owner.call("vault.shape.read", {});
    expect(shape.applies.some(apply => apply.seed_id === applied.seed_id)).toBe(true);
    const coOwnerAcceptance = await fed02Accept(coOwner, vaultId, "owner");
    await fed02Accept(admin, vaultId, "admin");
    const before = await owner.call("vault.shared.policy.get", { vault_id: vaultId });
    const deleteBefore = before.effective["delete_vault"];
    if (!deleteBefore) throw new Error("policy has no delete_vault row");
    expect(deleteBefore.wait_secs).toBe(defaultWaitSecs);
    expect(deleteBefore.objector_roles).toEqual(["owner"]);
    const eraseBefore = before.effective["erase"];
    if (!eraseBefore) throw new Error("policy has no erase row");
    expect(eraseBefore.wait_secs).toBe(defaultWaitSecs);
    expect(eraseBefore.objector_roles).toEqual(["owner"]);
    expect(before.effective["export"]).toBeUndefined();
    expect(await owner.call("vault.shared.owner_change_wait.get", {})).toBeNull();
    const hash = before.policy_hash;
    const shortPolicy: NonNullable<FacadeInput<"vault.shared.policy.propose">["policy"]> = {
      wait_secs: waitSecs,
      objector_roles: ["owner"],
      initiator_roles: ["owner"],
      policy_editor_roles: ["owner"],
      required_verb: "admin",
      starter_may_object: true,
      max_act_name_bytes: 128,
      max_payload_bytes: 1048576,
      precedence: "holder_may_narrow",
    };
    const proposed = await owner.call("vault.shared.policy.propose", {
      vault_id: vaultId, act: "delete_vault", policy: shortPolicy, expected_policy_hash: hash,
    });
    expect(proposed.state).toBe("pending");
    expect(proposed.proposer).toBe(ownerRef);
    expect(proposed.vault_id).toBe(vaultId);
    expect(proposed.act).toBe("delete_vault");
    expect(proposed.policy?.wait_secs).toBe(waitSecs);
    expect([...proposed.approvals].sort()).toEqual([ownerRef]);
    expect([...(proposed.awaiting ?? [])].sort()).toEqual([coOwnerRef]);
    const pending = await owner.call("vault.shared.policy.get", { vault_id: vaultId });
    const deletePending = pending.effective["delete_vault"];
    if (!deletePending) throw new Error("policy lost its delete_vault row while the change was pending");
    expect(deletePending.wait_secs).toBe(defaultWaitSecs);
    expect(pending.policy_hash).toBe(hash);
    await fed02Refused(admin.client, adminRef,
      () => admin.client.call("vault.shared.policy.answer", { change_id: proposed.id, approve: true }), 400, "BAD_REQUEST");
    const answered = await coOwner.client.call("vault.shared.policy.answer", { change_id: proposed.id, approve: true });
    expect(answered.state).toBe("applied");
    expect([...answered.approvals].sort()).toEqual([coOwnerRef, ownerRef].sort());
    expect(answered.awaiting ?? []).toEqual([]);
    expect(typeof answered.settled_at).toBe("number");
    const change = await owner.call("vault.shared.policy.change", { change_id: proposed.id });
    expect(change.id).toBe(proposed.id);
    expect(change.state).toBe("applied");
    expect([...change.approvals].sort()).toEqual([coOwnerRef, ownerRef].sort());
    const changes = await owner.call("vault.shared.policy.changes", { vault_id: vaultId });
    const listed = changes.find(row => row.id === proposed.id);
    if (!listed) throw new Error("applied policy change is not listed");
    expect(listed.state).toBe("applied");
    const after = await owner.call("vault.shared.policy.get", { vault_id: vaultId });
    const deleteAfter = after.effective["delete_vault"];
    if (!deleteAfter) throw new Error("policy lost its delete_vault row after the change applied");
    expect(deleteAfter).toEqual(shortPolicy);
    expect(after.policy_hash).not.toBe(hash);
    const act = await owner.call("vault.shared.propose_delete", { vault_id: vaultId });
    expect(act.act).toBe("delete_vault");
    expect(act.vault_id).toBe(vaultId);
    expect(act.starter).toBe(ownerRef);
    expect(act.deadline).toBe(act.started_at + waitSecs);
    expect(act.objector_roles).toEqual(["owner"]);
    expect(act.objections).toEqual([]);
    expect(act.completed).toBe(false);
    expect(act.execution ?? null).toBeNull();
    // The Admin refusal precedes a successful Owner objection, proving that the
    // same window was still open; receipt readback comes after the Owner acts.
    let adminObjectionFailure: unknown;
    try { await admin.client.call("vault.shared.object", { act_id: act.id }); }
    catch (error) { adminObjectionFailure = error; }
    const objected = await coOwner.client.call("vault.shared.object", { act_id: act.id });
    expect(objected.objections).toEqual([coOwnerRef]);
    expect(objected.completed).toBe(false);
    expect(objected.execution ?? null).toBeNull();
    const started = await coOwner.client.call("vault.shared.started", { vault_id: vaultId });
    const notice = started.find(row => row.act_id === act.id);
    if (!notice) throw new Error("co-Owner has no start notice for the act");
    expect(notice.vault_id).toBe(vaultId);
    expect(notice.act).toBe("delete_vault");
    expect(notice.recipient).toBe(coOwnerRef);
    expect(notice.deadline).toBe(act.deadline);
    await fed02Refused(admin.client, adminRef,
      async () => { throw adminObjectionFailure; }, 400, "BAD_REQUEST");
    const held = await owner.call("vault.shared.withdraw_objection", { act_id: act.id });
    expect(held.objections).toEqual([coOwnerRef]);
    expect(held.completed).toBe(false);
    expect(held.execution ?? null).toBeNull();
    await fed02Refused(owner, ownerRef,
      () => owner.call("vault.shared.execute", { act_id: act.id }), 409, "INVALID_STATE");
    expect(await owner.call("vault.shared.deletion", {})).toBeNull();
    await engine.restart();
    const durable = await owner.call("vault.shared.withdraw_objection", { act_id: act.id });
    expect(durable.objections).toEqual([coOwnerRef]);
    expect(durable.completed).toBe(false);
    expect(durable.execution ?? null).toBeNull();
    const startedAgain = await coOwner.client.call("vault.shared.started", { vault_id: vaultId });
    const noticeAgain = startedAgain.find(row => row.act_id === act.id);
    if (!noticeAgain) throw new Error("co-Owner start notice did not survive restart");
    expect(noticeAgain.deadline).toBe(act.deadline);
    await fed02Refused(owner, ownerRef,
      () => owner.call("vault.shared.execute", { act_id: act.id }), 409, "INVALID_STATE");
    expect(await owner.call("vault.shared.deletion", {})).toBeNull();
    const durablePolicy = await coOwner.client.call("vault.shared.policy.get", { vault_id: vaultId });
    const durableDelete = durablePolicy.effective["delete_vault"];
    if (!durableDelete) throw new Error("policy lost its delete_vault row across restart");
    expect(durableDelete).toEqual(shortPolicy);
    expect(durablePolicy.policy_hash).toBe(after.policy_hash);
    const durableReceipt = await coOwner.client.call("vault.shared.receipt", { receipt_id: coOwnerAcceptance.id });
    expect(durableReceipt.id).toBe(coOwnerAcceptance.id);
    expect(durableReceipt.vault_id).toBe(vaultId);
    expect(durableReceipt.actor).toBe(coOwnerRef);
    expect(durableReceipt.grants).toEqual(coOwnerAcceptance.grants);
    expect(durableReceipt.revoked_slips).toEqual([]);
    if (!("invitation_accepted" in durableReceipt.change)) throw new Error("durable acceptance receipt names no invitation_accepted change");
    if (!("invitation_accepted" in coOwnerAcceptance.change)) throw new Error("acceptance receipt names no invitation_accepted change");
    expect(durableReceipt.change.invitation_accepted.invitation).toBe(coOwnerAcceptance.change.invitation_accepted.invitation);
    expect(durableReceipt.change.invitation_accepted.member).toBe(coOwnerRef);
    expect(durableReceipt.change.invitation_accepted.role).toBe("owner");
  } finally {
    await engine.close();
  }
});

// FEDERATION-03 — Exact reciprocal relationship consent should work.
// OF-156/167; ARCH-0043#relationship-lifecycle.
type Fed03Direction = FacadeInput<"vault.federation.connect.offer">["outbound"];
type Fed03Scope = FacadeInput<"vault.federation.connect.grants.mint">["authority_scope"];
interface Fed03Fixture {
  readonly cases: readonly {
    readonly id: string;
    readonly inputs: {
      readonly matchingProposal: { readonly hostToGuestWorlds: readonly string[]; readonly guestToHostWorlds: readonly string[] };
      readonly proposalB: { readonly hostToGuestWorlds: readonly string[] };
      readonly narrowTo: { readonly guestToHostCeiling: { readonly kind: "bottom" } };
    };
  }[];
}
// Fixed authored past claim time, not a caller clock or an engine setting.
const FED03_LEARNED_AT = 1792238400;
const FED03_PREDICATE = "federation.delivery";
function fed03Direction(worlds: string[]): Fed03Direction {
  return { worlds: { kind: "some", values: worlds }, facets: { kind: "all" }, bands: { kind: "all" } };
}
function fed03ShareScope(world: string): Fed03Scope {
  return {
    worlds: { kind: "some", values: [world] }, facets: { kind: "all" }, bands: { kind: "all" },
    audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] },
    sensitivity: { kind: "at_most", value: "private" },
  };
}
async function fed03NamedWorld(engine: EngineFixture, name: string): Promise<string> {
  const world = await engine.client.call("vault.structural.put", {
    kind: "WORLD", body: { name, kind: "fictional" }, occurred_at: FED03_LEARNED_AT,
    text_fields: [{ field: "name", value: name }],
  });
  const read = await engine.client.call("vault.get", { entity_ref: world.entity_ref });
  expect(read.value?.kind).toBe("WORLD");
  expect(read.value?.id_hex).toBe(world.id_hex);
  expect(read.value?.body).toMatchObject({ name, kind: "fictional" });
  return world.id_hex;
}
async function fed03Status(engine: EngineFixture, pact: string, status: "Active" | "Disconnected", epoch: number): Promise<void> {
  const read = await engine.client.call("vault.federation.status", {});
  expect(read.pacts.find(row => row.pact === pact)).toEqual({ pact, status, epoch, inactive_reason: null });
}
/** Every authenticated refusal has its real facade call receipt, read as owner. */
async function fed03Refusal(engine: EngineFixture, attempt: Promise<unknown>, status: number, code: string,
  actor: string, verb: string): Promise<PublicHttpError> {
  let refusal: PublicHttpError;
  try {
    await attempt;
    throw new Error("Expected the public call to refuse");
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  expect(refusal.reply.status).toBe(status);
  expect(refusal.error?.code).toBe(code);
  const receiptRef = refusal.reply.headers.get("x-oneiron-receipt-ref");
  if (!receiptRef) throw new Error("Authenticated refusal has no call receipt");
  expect(refusal.error?.["receiptRef"]).toBe(receiptRef);
  const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
  expect(receipt?.receipt_ref).toBe(receiptRef);
  expect(receipt?.actor_ref).toBe(actor);
  expect(receipt?.transport).toBe("http_facade");
  expect(receipt?.verb).toBe(verb);
  expect(receipt?.outcome).toEqual({ refused: { code } });
  return refusal;
}
async function fed03PermitImported(engine: EngineFixture): Promise<void> {
  const policy = await engine.client.call("vault.gate.policy.get", {});
  const row = policy.manifests.find(item => item.manifest_ref === policy.default_manifest_ref);
  if (!row) throw new Error("No default policy manifest");
  const permit = { max_auto_sensitivity: 1, receipted: true, warned: true };
  const written = await engine.client.call("vault.gate.policy.put", {
    manifest_ref: row.manifest_ref, expected_body_hash: row.body_hash,
    manifest: { ...row.manifest, source_trust: { ...(row.manifest.source_trust ?? {}), imported: permit } },
  });
  expect(written.receipt_ref.length).toBeGreaterThan(0);
  const after = await engine.client.call("vault.gate.policy.get", { manifest_ref: row.manifest_ref });
  const saved = after.manifests.find(item => item.manifest_ref === row.manifest_ref);
  expect(saved?.trusted).toBe(true);
  expect(saved?.quarantined).toBe(false);
  expect(saved?.manifest.source_trust?.["imported"]).toEqual(permit);
}
async function fed03Deliver(source: EngineFixture, recipient: EngineFixture, pact: string,
  world: string, sourceVault: string, recipientVault: string, sentence: string): Promise<FacadeResult<"vault.federation.connect.export">> {
  const scope = await ownerBaseClaimScope(source.client, source.pairedActor.principalRef);
  const written = await source.client.call("vault.claims.upsert", {
    predicate: FED03_PREDICATE, subject_ref: source.pairedActor.principalRef, value: sentence,
    confidence: 0.9, source: "user_stated", sensitivity: 1, scope: { ...scope, world_id: world },
    occurred_at: FED03_LEARNED_AT, learned_at: FED03_LEARNED_AT,
  });
  // A sensitivity-stamped claim requests Proposed (memory/support/wire.rs:59-71); it still syncs.
  expect(written.approval).toBe("proposed");
  const delivery = await source.client.call("vault.federation.connect.export", {
    pact, window_key: `2026-10@${world}`, world_ref: world,
  });
  expect(delivery.body).toMatchObject({ pact, epoch: 1, source_vault: sourceVault, recipient_vault: recipientVault, world_ref: world });
  expect(delivery.signature.length).toBeGreaterThan(0);
  expect(delivery.body.update.length).toBeGreaterThan(0);
  const joined = await recipient.client.call("vault.federation.connect.rejoin", delivery);
  expect(joined).toMatchObject({ pact, epoch: 1, status: "imported" });
  expect(joined.world_ref).not.toBe(world);
  const page = await awaitPublic(
    () => recipient.client.call("vault.claims.list", { predicate: FED03_PREDICATE, limit: 20 }),
    value => value.value.some(row => row.world_ref === joined.world_ref && row.value === sentence),
    { label: "FEDERATION-03 signed claim visible in recipient foreign world" },
  );
  const received = page.value.filter(row => row.world_ref === joined.world_ref && row.value === sentence);
  expect(received).toHaveLength(1);
  expect(received[0]?.approval).toBe("proposed");
  expect(received[0]?.source).toBe("imported");
  expect(received[0]?.lifecycle).toBe("active");
  return delivery;
}

/* Promise: mismatched disclosure refuses; matching owner-carried Connect halves deliver both ways; local narrowing and disconnect refuse the next excluded use, including local closure after restart.
 * Doors: typed Connect, federation.status, structural.put/get, gate.policy.put/get, claims.upsert/list, receipts.get, pairActor and restart.
 * Unproved: add-world grant widening, automatic peer lifecycle admission, unrelated inbound delivery after outbound Bottom, and guest document/proposal access; this partial names none of them.
 */
suite.test(test, "FEDERATION-03", "Mismatched grant disclosure is refused; matching owner-carried Connect halves deliver foreign claims, and local narrowing and disconnect refuse the next excluded use", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<Fed03Fixture>("federation-canon-scenarios");
  const scenario = fixture.cases.find(row => row.id === "FEDERATION-03");
  if (!scenario) throw new Error("No FEDERATION-03 scenario");
  const sharedName = scenario.inputs.matchingProposal.hostToGuestWorlds[0];
  const guestName = scenario.inputs.matchingProposal.guestToHostWorlds[0];
  const unsharedName = scenario.inputs.proposalB.hostToGuestWorlds.find(name => name !== sharedName);
  if (!sharedName || !guestName || !unsharedName) throw new Error("FEDERATION-03 needs its three named-world labels");
  const engine = await EngineFixture.start({ id: "FEDERATION-03", profile, peers: 1 });
  try {
    const peer = engine.peers[0]!;
    const hostId = await engine.client.call("vault.federation.connect.identity", {});
    const peerId = await peer.client.call("vault.federation.connect.identity", {});
    expect(hostId.vault).not.toBe(peerId.vault);
    const sharedWorld = await fed03NamedWorld(engine, sharedName);
    const unsharedWorld = await fed03NamedWorld(engine, unsharedName);
    const guestWorld = await fed03NamedWorld(peer, guestName);
    const hostScope = fed03ShareScope(sharedWorld);
    const peerScope = fed03ShareScope(guestWorld);
    const hostGrant = await engine.client.call("vault.federation.connect.grants.mint", { peer_vault: peerId.vault, authority_scope: hostScope });
    const peerGrant = await peer.client.call("vault.federation.connect.grants.mint", { peer_vault: hostId.vault, authority_scope: peerScope });
    expect(hostGrant.resolved_scope).toEqual(hostScope);
    expect(peerGrant.resolved_scope).toEqual(peerScope);
    for (const [side, grant] of [[engine, hostGrant], [peer, peerGrant]] as const) {
      expect((await side.client.call("vault.get", { entity_ref: grant.grant })).value?.kind).toBe("FEDERATION_GRANT");
      expect((await side.client.call("vault.get", { entity_ref: grant.guest_actor })).value?.kind).toBe("PERSON");
    }

    // B's real signed offer asks A to disclose H+U; A's grant discloses only H.
    const mismatch = await peer.client.call("vault.federation.connect.offer", {
      peer_vault: hostId.vault, grant: peerGrant.grant,
      outbound: fed03Direction([guestWorld]), inbound: fed03Direction([sharedWorld, unsharedWorld]),
    });
    const refused = await fed03Refusal(engine, engine.client.call("vault.federation.connect.accept", {
      offer: mismatch, grant: hostGrant.grant,
    }), 400, "BAD_REQUEST", engine.pairedActor.principalRef, "vault.federation.connect.accept");
    expect(refused.error?.message).toContain("the pact's outbound scope is not the Connect grant's scope");
    for (const side of [engine, peer]) {
      expect((await side.client.call("vault.federation.status", {})).pacts.some(row => row.pact === mismatch.pact)).toBe(false);
    }

    const offer = await engine.client.call("vault.federation.connect.offer", {
      peer_vault: peerId.vault, grant: hostGrant.grant,
      outbound: fed03Direction([sharedWorld]), inbound: fed03Direction([guestWorld]),
    });
    const peerAccept = await peer.client.call("vault.federation.connect.accept", { offer, grant: peerGrant.grant });
    const hostAccept = await engine.client.call("vault.federation.connect.accept", { offer: peerAccept.counter, grant: hostGrant.grant });
    expect(peerAccept).toMatchObject({ pact: offer.pact, status: "Active", peer_key: hostId.host_key });
    expect(hostAccept).toMatchObject({ pact: offer.pact, status: "Active", peer_key: peerId.host_key });
    await fed03Status(engine, offer.pact, "Active", 1);
    await fed03Status(peer, offer.pact, "Active", 1);

    const hostExport = { pact: offer.pact, window_key: `2026-10@${sharedWorld}`, world_ref: sharedWorld };
    const guest = await engine.pairActor({ principalRef: hostGrant.guest_actor, actorClass: "human", scope: ["core:read", "core:write"] });
    await fed03Refusal(engine, guest.client.call("vault.federation.connect.export", hostExport),
      403, "FORBIDDEN", guest.principalRef, "vault.federation.connect.export");
    await fed03PermitImported(engine);
    await fed03PermitImported(peer);
    await fed03Deliver(engine, peer, offer.pact, sharedWorld, hostId.vault, peerId.vault, "The host shared the federation observatory plan.");
    const peerDelivery = await fed03Deliver(peer, engine, offer.pact, guestWorld, peerId.vault, hostId.vault, "The peer shared the federation workshop plan.");

    const narrowed = await peer.client.call("vault.federation.connect.narrow", {
      pact: offer.pact, epoch: 1,
      outbound: { worlds: scenario.inputs.narrowTo.guestToHostCeiling, facets: { kind: "all" }, bands: { kind: "all" } },
    });
    expect(narrowed).toMatchObject({ pact: offer.pact, status: "Active", epoch: 1, effective_scope: { worlds: { kind: "bottom" } } });
    // This is the very next use of B's now-excluded outbound world.
    await fed03Refusal(peer, peer.client.call("vault.federation.connect.export", {
      pact: offer.pact, window_key: `2026-10@${guestWorld}`, world_ref: guestWorld,
    }), 400, "BAD_REQUEST", peer.pairedActor.principalRef, "vault.federation.connect.export");
    await fed03Status(peer, offer.pact, "Active", 1);

    const disconnected = await engine.client.call("vault.federation.connect.disconnect", { pact: offer.pact });
    expect(disconnected.receipt).toMatchObject({ pact: offer.pact, status: "Disconnected", epoch: 1 });
    expect(disconnected).toMatchObject({ outbound_access: false, inbound_access: false, sync_stopped: true, copied_bytes_recallable: false, recipient_copy_state: "unknown" });
    // The next local uses in BOTH directions must refuse, without B's help.
    await fed03Refusal(engine, engine.client.call("vault.federation.connect.export", hostExport),
      400, "BAD_REQUEST", engine.pairedActor.principalRef, "vault.federation.connect.export");
    await fed03Refusal(engine, engine.client.call("vault.federation.connect.rejoin", peerDelivery),
      400, "BAD_REQUEST", engine.pairedActor.principalRef, "vault.federation.connect.rejoin");
    await fed03Status(engine, offer.pact, "Disconnected", 1);
    await fed03Status(peer, offer.pact, "Active", 1);
    await engine.restart();
    await fed03Status(engine, offer.pact, "Disconnected", 1);
    await fed03Refusal(engine, engine.client.call("vault.federation.connect.export", hostExport),
      400, "BAD_REQUEST", engine.pairedActor.principalRef, "vault.federation.connect.export");
  } finally {
    await engine.close();
  }
});

// FEDERATION-04 — Guest share cannot reshare or reveal topology should work.
// OF-141/153/154/069/232; ARCH-0043#guest-grants/#relationship-lifecycle.
type Fed04Scope = FacadeInput<"vault.federation.connect.grants.mint">["authority_scope"];
type Fed04Direction = FacadeInput<"vault.federation.connect.offer">["outbound"];
type Fed04Envelope = FacadeResult<"vault.guests.share">;
type Fed04Grant = FacadeResult<"vault.federation.connect.grants.mint">;
interface Fed04Scenarios {
  readonly cases: readonly {
    readonly id: string;
    readonly inputs: { readonly sharedDocument?: unknown };
  }[];
}
interface Fed04Pact {
  readonly pact: string;
  readonly hostVault: string;
  readonly guestVault: string;
  readonly hostKey: string;
  readonly world: string;
  readonly grant: Fed04Grant;
  readonly direction: Fed04Direction;
}

/** Test-authored learn time (2026-10-17T12:00:00Z): the claim's world window is
 * then known without reading a clock. Claims honour a supplied past learned_at. */
const FED04_LEARNED_AT = 1792238400;
const FED04_PREDICATE = "federation.fixture.document";
const FED04_HEX32 = /^[0-9a-f]{32}$/;
const FED04_HEX64 = /^[0-9a-f]{64}$/;

/** A Connect guest grant over one named world: read and propose, at most
 * private, every other axis explicit (an omitted Scope axis deserializes as
 * bottom). Verbs are pre-sorted: the wire carries a sorted set. */
function fed04ShareScope(world: string): Fed04Scope {
  return {
    worlds: { kind: "some", values: [world] },
    facets: { kind: "all" },
    bands: { kind: "all" },
    audience: { kind: "all" },
    verbs: { kind: "some", values: ["propose", "read"] },
    sensitivity: { kind: "at_most", value: "private" },
  };
}
/** The pact half a grant above projects to; offer/accept require it exactly. */
function fed04Direction(world: string): Fed04Direction {
  return {
    worlds: { kind: "some", values: [world] },
    facets: { kind: "all" },
    bands: { kind: "all" },
  };
}
/** "YYYY-MM@<world hex>": the world-scoped monthly window a CLAIM lives in. */
function fed04WindowKey(learnedAt: number, world: string): string {
  return `${new Date(learnedAt * 1000).toISOString().slice(0, 7)}@${world}`;
}
async function fed04Refusal(attempt: Promise<unknown>, engine: EngineFixture, receipted = true): Promise<PublicHttpError> {
  try {
    await attempt;
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    if (receipted) {
      const receiptRef = error.reply.headers.get("x-oneiron-receipt-ref");
      expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
      if (!receiptRef) throw new Error("Authenticated refusal has no call receipt");
      expect(error.error?.receiptRef).toBe(receiptRef);
      const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
      if (!receipt) throw new Error("Refusal receipt was not readable by the owner");
      expect(receipt.receipt_ref).toBe(receiptRef);
      expect(receipt.transport).toBe("http_facade");
      const refusedCode = error.error?.code;
      if (!refusedCode) throw new Error("Refusal carries no error code");
      expect(receipt.outcome).toEqual({ refused: { code: refusedCode } });
    }
    return error;
  }
  throw new Error("expected a public refusal; the call succeeded");
}
async function fed04NamedWorld(engine: EngineFixture, name: string): Promise<string> {
  const world = await engine.client.call("vault.structural.put", {
    kind: "WORLD",
    body: { name, kind: "fictional" },
    occurred_at: FED04_LEARNED_AT,
    text_fields: [{ field: "name", value: name }],
  });
  expect(world.id_hex).toMatch(FED04_HEX32);
  expect(world.entity_ref.length).toBeGreaterThan(0);
  const read = await engine.client.call("vault.get", { entity_ref: world.entity_ref });
  if (!read.value) throw new Error("Created WORLD is not publicly readable");
  expect(read.value.kind).toBe("WORLD");
  expect(read.value.id_hex).toBe(world.id_hex);
  expect(read.value.body).toMatchObject({ name, kind: "fictional" });
  return world.id_hex;
}
/** Both owners carry each signed half; each host sends nothing (FIX 323/3016). */
async function fed04ConnectPact(host: EngineFixture, guest: EngineFixture): Promise<Fed04Pact> {
  const hostId = await host.client.call("vault.federation.connect.identity", {});
  const guestId = await guest.client.call("vault.federation.connect.identity", {});
  expect(hostId.vault).toMatch(FED04_HEX64);
  expect(hostId.host_key).toMatch(FED04_HEX64);
  expect(guestId.vault).toMatch(FED04_HEX64);
  expect(hostId.vault).not.toBe(guestId.vault);
  const world = await fed04NamedWorld(host, "FEDERATION-04 shared observatory");
  const guestWorld = await fed04NamedWorld(guest, "FEDERATION-04 guest observatory");
  const grant = await host.client.call("vault.federation.connect.grants.mint", {
    peer_vault: guestId.vault,
    authority_scope: fed04ShareScope(world),
  });
  expect(grant.grant).toMatch(FED04_HEX32);
  expect(grant.guest_actor).toMatch(FED04_HEX32);
  expect(grant.expires_at ?? null).toBeNull();
  const guestGrant = await guest.client.call("vault.federation.connect.grants.mint", {
    peer_vault: hostId.vault,
    authority_scope: fed04ShareScope(guestWorld),
  });
  const direction = fed04Direction(world);
  const offer = await host.client.call("vault.federation.connect.offer", {
    peer_vault: guestId.vault,
    grant: grant.grant,
    outbound: direction,
    inbound: fed04Direction(guestWorld),
  });
  expect(offer.pact).toMatch(FED04_HEX64);
  const guestAccepted = await guest.client.call("vault.federation.connect.accept", {
    offer,
    grant: guestGrant.grant,
  });
  expect(guestAccepted.pact).toBe(offer.pact);
  expect(guestAccepted.status).toBe("Active");
  const hostAccepted = await host.client.call("vault.federation.connect.accept", {
    offer: guestAccepted.counter,
    grant: grant.grant,
  });
  expect(hostAccepted.pact).toBe(offer.pact);
  expect(hostAccepted.status).toBe("Active");
  for (const side of [host, guest]) {
    const status = await side.client.call("vault.federation.status", {});
    expect(status.pacts.filter((row) => row.status === "Active" && row.epoch === 1)).toHaveLength(1);
  }
  return {
    pact: offer.pact,
    hostVault: hostId.vault,
    guestVault: guestId.vault,
    hostKey: hostId.host_key,
    world,
    grant,
    direction,
  };
}
/** The guest's own Ed25519 holder key, generated on its own device: the mint
 * binds the public half, and the guest proves each request with the seed. */
function fed04GuestKeys(): { holderKeyHex: string; seedHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x;
  const d = privateKey.export({ format: "jwk" }).d;
  if (typeof x !== "string" || typeof d !== "string") throw new Error("ed25519 JWK export has no key material");
  const holderKeyHex = Buffer.from(x, "base64url").toString("hex");
  const seedHex = Buffer.from(d, "base64url").toString("hex");
  expect(holderKeyHex).toMatch(FED04_HEX64);
  expect(seedHex).toMatch(FED04_HEX64);
  return { holderKeyHex, seedHex };
}
/** Every field of one fetched envelope: pact, epoch, ceiling, effective scope,
 * recipient, window, both 64-byte signatures, and its own travel digest. Each
 * export builds a fresh document, so callers compare digests, never bytes. */
function fed04ExpectEnvelope(envelope: Fed04Envelope, pact: Fed04Pact, windowKey: string): void {
  expect(envelope.context.pact).toBe(pact.pact);
  expect(envelope.context.epoch).toBe(1);
  expect(envelope.context.ceiling).toEqual(pact.grant.resolved_scope);
  expect(envelope.context.effective_scope).toEqual(pact.direction);
  expect(envelope.envelope.body.member_ref).toBe(pact.grant.guest_actor);
  expect(envelope.envelope.body.scope).toEqual({
    Connect: { peer_vault_id: [...Buffer.from(pact.guestVault, "hex")] },
  });
  expect(envelope.envelope.body.window_key).toBe(windowKey);
  expect(envelope.envelope.body.update.length).toBeGreaterThan(0);
  expect(envelope.envelope.body.selector.length).toBeGreaterThan(0);
  expect(envelope.envelope.signature).toHaveLength(64);
  expect(envelope.signer).toBe(pact.hostKey);
  expect(envelope.signature).toHaveLength(64);
  const body = envelope.envelope.body;
  const canonicalBody = encode({
    schema_version: 1,
    scope: { kind: "connect", peer_vault_id: pact.guestVault },
    member_ref: body.member_ref,
    selector: Uint8Array.from(body.selector),
    window_key: body.window_key,
    update: Uint8Array.from(body.update),
  });
  const hostKey = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pact.hostKey, "hex")]),
    format: "der", type: "spki",
  });
  expect(verify(null, canonicalBody, hostKey, Uint8Array.from(envelope.envelope.signature))).toBe(true);
  const canonicalEnvelope = encode({ body: canonicalBody, signature: Uint8Array.from(envelope.envelope.signature) });
  const context = {
    pact: envelope.context.pact, epoch: envelope.context.epoch,
    ceiling: {
      worlds: envelope.context.ceiling.worlds,
      facets: envelope.context.ceiling.facets,
      bands: envelope.context.ceiling.bands,
      audience: envelope.context.ceiling.audience,
      verbs: envelope.context.ceiling.verbs,
      sensitivity: envelope.context.ceiling.sensitivity,
    },
    effective_scope: {
      worlds: envelope.context.effective_scope.worlds,
      facets: envelope.context.effective_scope.facets,
      bands: envelope.context.effective_scope.bands,
    },
  };
  // The inner rmpv codec uses binary fields; the outer serde &[u8] is a sequence.
  const transcript = encode(["oneiron/guest-document/v1", context, [...canonicalEnvelope]]);
  expect(verify(null, transcript, hostKey, Uint8Array.from(envelope.signature))).toBe(true);
  const note = envelope.travel_receipt;
  expect(note).not.toBeNull();
  if (!note) throw new Error("guest export has no travel note");
  expect(note.content_hash).toBe(
    Buffer.from(blake3(Uint8Array.from(envelope.envelope.body.update))).toString("hex"),
  );
  expect(typeof note.receipt_owed).toBe("boolean");
}

/** A guest's WS connect that explains its own refusal. Bun's WS client
 * reports a refused upgrade only as "WS upgrade failed", so on failure the
 * same upgrade is re-issued as a raw HTTP GET /ws (the authority.test.ts
 * refusedUpgrade shape) to carry the real status, error code and message.
 * The sync upgrade names no JSON body today (a bare 401/403), so the
 * diagnosis reports status, headers and raw text, never an assumed body. */
async function fed04GuestSocket(
  origin: string,
  guestCredential: string,
  guestClient: PublicHttpClient,
): Promise<WsClient> {
  try {
    return await WsClient.connect(origin, guestCredential);
  } catch (upgradeError) {
    let diagnosis: string;
    try {
      const probe = await guestClient.raw("GET", "/ws", undefined, {
        connection: "Upgrade",
        upgrade: "websocket",
        "sec-websocket-version": "13",
        "sec-websocket-key": Buffer.from(secretHex(16), "hex").toString("base64"),
      });
      const outcome = probe.body as { error?: { code?: unknown; message?: unknown } } | null;
      const code = typeof outcome === "object" && outcome !== null ? outcome.error?.code : undefined;
      const message =
        typeof outcome === "object" && outcome !== null ? outcome.error?.message : undefined;
      const receipt = probe.headers.get("x-oneiron-receipt-ref") ?? "none";
      const raw = probe.raw.length > 300 ? `${probe.raw.slice(0, 300)}...` : probe.raw;
      diagnosis =
        `HTTP ${probe.status}` +
        ` code=${typeof code === "string" ? code : "none"}` +
        ` message=${typeof message === "string" ? message : "none"}` +
        ` receipt=${receipt}` +
        ` raw=${JSON.stringify(raw)}`;
    } catch (probeError) {
      const detail = probeError instanceof Error ? probeError.message : String(probeError);
      diagnosis = `HTTP probe of GET /ws failed: ${detail}`;
    }
    throw new Error(`FEDERATION-04 ENGINE DEFECT 2026-11-10: scoped guest cannot reach WS facade admission (${diagnosis})`, {
      cause: upgradeError,
    });
  }
}

/* FEDERATION-04 — decision: WRITTEN (partial).
 * Promise: a live Connect guest can fetch its signed scoped envelope;
 *   revocation reports that copies are not recallable and stops the guest's
 *   next fetch and proposal.
 * Doors: vault.structural.put (WORLD) + vault.get read-back,
 *   vault.federation.connect.identity / grants.mint / offer / accept,
 *   vault.federation.status, vault.receipts.get, vault.claims.upsert/list, vault.guests.mint_slip /
 *   share / export_envelope / propose / revoke (typed facade),
 *   POST /v1/owner/guests/revoke (raw owner route), guest WS
 *   export_envelope, restart.
 * Unproved and why: decoded payload hides nothing (needs a consumer Loro wire
 *   decoder in the suite; byte scans prove no topology claim).
 *   A valid guest-authored text proposal landing pre-revoke (needs a public
 *   guest text-proposal encoding door behind the live guest grant).
 *   Foreign-world reshare refused, and a host control share to a third vault
 *   (needs a third vault with two more pacts; no missing verb identified).
 *   Guest-envelope admission into the guest vault's own store (needs a public
 *   guest-envelope admission verb behind the receiving grant).
 */
suite.test(test, "FEDERATION-04", "A live Connect guest can fetch its signed scoped envelope; revocation reports that copies are not recallable and stops the guest's next fetch and proposal", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<Fed04Scenarios>("federation-canon-scenarios");
  const sharedSentence = fixture.cases.find((row) => row.id === "FEDERATION-04")?.inputs.sharedDocument;
  if (typeof sharedSentence !== "string") throw new Error("federation-canon-scenarios has no FEDERATION-04 sharedDocument");
  const engine = await EngineFixture.start({ id: "FEDERATION-04", profile, peers: 1 });
  let guestSocket: WsClient | undefined;
  try {
    const guestVault = engine.peers[0];
    if (!guestVault) throw new Error("FEDERATION-04 needs its peer vault");
    const pact = await fed04ConnectPact(engine, guestVault);
    // Mint refuses an excess scope rather than clamping it: the stored grant
    // is exactly what was asked (verb sets compare unordered).
    const resolved = pact.grant.resolved_scope;
    expect(resolved.worlds).toEqual({ kind: "some", values: [pact.world] });
    expect(resolved.facets).toEqual({ kind: "all" });
    expect(resolved.bands).toEqual({ kind: "all" });
    expect(resolved.audience).toEqual({ kind: "all" });
    const verbs = resolved.verbs;
    if (!verbs || verbs.kind !== "some") throw new Error("grant verbs narrowed unexpectedly");
    expect([...verbs.values].sort()).toEqual(["propose", "read"]);
    expect(resolved.sensitivity).toEqual({ kind: "at_most", value: "private" });
    // The host's own claim in the shared world. Sensitivity 1 (private) keeps
    // it inside the grant's at-most-private ceiling.
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const shared = await engine.client.call("vault.claims.upsert", {
      predicate: FED04_PREDICATE,
      subject_ref: engine.pairedActor.principalRef,
      value: sharedSentence,
      confidence: 0.9,
      source: "user_stated",
      sensitivity: 1,
      scope: { ...scope, world_id: pact.world },
      occurred_at: FED04_LEARNED_AT,
      learned_at: FED04_LEARNED_AT,
    });
    expect(shared.claim_short_id.length).toBeGreaterThan(0);
    const sharedRead = await engine.client.call("vault.claims.list", { predicate: FED04_PREDICATE, limit: 10 });
    expect(sharedRead.value).toHaveLength(1);
    const sharedRow = sharedRead.value[0];
    if (!sharedRow) throw new Error("Shared setup claim is not publicly readable");
    expect(sharedRow.value).toBe(sharedSentence);
    expect(sharedRow.subject_ref).toBe(engine.pairedActor.principalRef);
    expect(sharedRow.world_ref).toBe(pact.world);
    expect(sharedRow.source).toBe("user_stated");
    expect(sharedRow.lifecycle).toBe("active");
    const windowKey = fed04WindowKey(FED04_LEARNED_AT, pact.world);
    const request: FacadeInput<"vault.guests.share"> = {
      grant_ref: pact.grant.grant,
      world_ref: pact.world,
      window_key: windowKey,
      facets: [],
      bands: [],
    };
    // The guest's own key; the host mints the slip that binds it.
    const { holderKeyHex, seedHex } = fed04GuestKeys();
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const minted = await engine.client.call("vault.guests.mint_slip", {
      grant_ref: pact.grant.grant,
      holder_key: holderKeyHex,
      expires_at: expiresAt,
    });
    expect(minted.slip.startsWith("v2.slip.")).toBe(true);
    expect(minted.slip_id).toMatch(FED04_HEX64);
    expect(minted.expires_at).toBe(expiresAt);
    const guestCredential = `v2.cred.${minted.slip.slice(8)}.${seedHex}`;
    const guestClient = new PublicHttpClient(engine.url, {
      credential: guestCredential,
      artifacts: engine.artifacts,
      label: "fed04-guest",
    });
    guestSocket = await fed04GuestSocket(engine.url, guestCredential, guestClient);

    // Act: the owner shares. Second doors: the guest fetches over HTTP and WS.
    const sharedEnvelope = await engine.client.call("vault.guests.share", request);
    fed04ExpectEnvelope(sharedEnvelope, pact, windowKey);
    const fetched = await guestClient.call("vault.guests.export_envelope", request);
    fed04ExpectEnvelope(fetched, pact, windowKey);
    const socketFetched = await guestSocket.call("vault.guests.export_envelope", request);
    expect(socketFetched.frames.length).toBeGreaterThan(0);
    fed04ExpectEnvelope(socketFetched.value, pact, windowKey);

    // Wrong-actor refusals include status, code and a call receipt read as owner.
    const ownerExport = await fed04Refusal(engine.client.call("vault.guests.export_envelope", request), engine);
    expect(ownerExport.reply.status).toBe(403);
    expect(ownerExport.error?.code).toBe("FORBIDDEN");
    const guestShare = await fed04Refusal(guestClient.call("vault.guests.share", request), engine);
    expect(guestShare.reply.status).toBe(403);
    expect(guestShare.error?.code).toBe("FORBIDDEN");
    const unsharedWorld = await fed04NamedWorld(engine, "FEDERATION-04 unshared observatory");
    const outsideWindowKey = fed04WindowKey(FED04_LEARNED_AT, unsharedWorld);
    const outsideGrant = await fed04Refusal(engine.client.call("vault.guests.share", {
      ...request,
      world_ref: unsharedWorld,
      window_key: outsideWindowKey,
    }), engine);
    expect(outsideGrant.reply.status).toBe(403);
    expect(outsideGrant.error?.code).toBe("FORBIDDEN");

    // Revoke mid-flow; the receipt is honest about already-synced copies.
    const revoked = await engine.client.call("vault.guests.revoke", { grant_ref: pact.grant.grant });
    expect(revoked.grant_ref).toBe(pact.grant.grant);
    expect(revoked.guest_ref).toBe(pact.grant.guest_actor);
    expect(revoked.changed).toBe(true);
    expect(revoked.revoked_at).toBeGreaterThan(0);
    expect(revoked.revoked_slip_refs ?? []).toContain(minted.slip_id);
    expect(revoked.pact_standing).toBe("disconnected");
    expect(revoked.disclosure.copied_bytes_recallable).toBe(false);
    expect(revoked.disclosure.recipient_copy_state).toBe("unknown");
    expect(revoked.disclosure.deletion_request_status).toBe("not_requested");
    const targets = revoked.courtesy_targets ?? [];
    expect(targets).toHaveLength(1);
    const [target] = targets;
    if (!target) throw new Error("revoke names no ended pact");
    expect(target.pact).toBe(pact.pact);
    expect(target.peer_vault_id).toBe(pact.guestVault);
    expect(target.epoch_cutoff).toBe(1);
    expect(target.deletion_request_status).toBe("not_requested");
    expect(target.request ?? null).toBeNull();

    // Owner read-back through other doors: the raw route repeats the first
    // revoke, the pact stands disconnected, and the grant is gone.
    const repeatRaw = await engine.client.raw("POST", "/v1/owner/guests/revoke", { grant_ref: pact.grant.grant });
    expect(repeatRaw.status).toBe(200);
    const repeat = repeatRaw.body as Facade.GuestRevokeResponse;
    expect(repeat.grant_ref).toBe(pact.grant.grant);
    expect(repeat.changed).toBe(false);
    expect(repeat.revoked_at).toBe(revoked.revoked_at);
    expect(repeat.revoked_slip_refs ?? []).toEqual([]);
    const standing = await engine.client.call("vault.federation.status", {});
    const ended = standing.pacts.find((row) => row.pact === pact.pact);
    expect(ended?.status).toBe("Disconnected");
    expect(ended?.epoch).toBe(1);
    const grantGone = await fed04Refusal(engine.client.call("vault.guests.share", request), engine);
    expect(grantGone.reply.status).toBe(404);
    expect(grantGone.error?.code).toBe("NOT_FOUND");

    // The guest's next fetch and proposal stop at authentication.
    const fetchStopped = await fed04Refusal(guestClient.call("vault.guests.export_envelope", request), engine, false);
    expect(fetchStopped.reply.status).toBe(401);
    expect(fetchStopped.error?.code).toBe("UNAUTHORIZED");
    const proposeStopped = await fed04Refusal(
      guestClient.call("vault.guests.propose", {
        grant_ref: pact.grant.grant,
        world_ref: pact.world,
        entity_ref: pact.world,
        update: [],
      }), engine, false,
    );
    expect(proposeStopped.reply.status).toBe(401);
    expect(proposeStopped.error?.code).toBe("UNAUTHORIZED");
    // The held socket serves no more RPC: it closes instead of answering.
    const revokedSocket = guestSocket;
    await expect(revokedSocket.call("vault.guests.export_envelope", request)).rejects.toThrow(/WS closed /);
    await awaitPublic(
      async () => revokedSocket.socket.readyState,
      (state) => state === WebSocket.CLOSED,
      { label: "revoked guest socket closed by server" },
    );
    revokedSocket.close();
    guestSocket = undefined;

    // Restart keeps the revocation: no revived fetch, no revived grant.
    await engine.restart();
    const fetchAfterRestart = await fed04Refusal(guestClient.call("vault.guests.export_envelope", request), engine, false);
    expect(fetchAfterRestart.reply.status).toBe(401);
    expect(fetchAfterRestart.error?.code).toBe("UNAUTHORIZED");
    const shareAfterRestart = await fed04Refusal(engine.client.call("vault.guests.share", request), engine);
    expect(shareAfterRestart.reply.status).toBe(404);
    expect(shareAfterRestart.error?.code).toBe("NOT_FOUND");
    const standingAfterRestart = await engine.client.call("vault.federation.status", {});
    const endedAfterRestart = standingAfterRestart.pacts.find((row) => row.pact === pact.pact);
    expect(endedAfterRestart?.status).toBe("Disconnected");

    await engine.artifacts.json("federation-04.json", {
      pact: pact.pact,
      world: pact.world,
      windowKey,
      guestActor: pact.grant.guest_actor,
      contentHashes: [sharedEnvelope, fetched, socketFetched.value].map((row) => row.travel_receipt?.content_hash ?? null),
      updateLengths: [sharedEnvelope, fetched, socketFetched.value].map((row) => row.envelope.body.update.length),
      wsFrames: socketFetched.frames.length,
      revoked: { changed: revoked.changed, pact_standing: revoked.pact_standing, disclosure: revoked.disclosure },
      refusals: {
        ownerExport: ownerExport.reply.status,
        guestShare: guestShare.reply.status,
        outsideGrant: outsideGrant.reply.status,
        grantGone: grantGone.reply.status,
        fetchStopped: fetchStopped.reply.status,
        proposeStopped: proposeStopped.reply.status,
      },
    });
  } finally {
    guestSocket?.close();
    await engine.close();
  }
});

// FEDERATION-05 — Cross-vault identity without pooled truth should work.
// OF-151; ARCH-0043#quarantine-and-coreference/#relationship-lifecycle.
/* FEDERATION-05 stays TODO: the promise is "A confirmed cross-vault identity link never pools independently authored city claims through PPR in either orientation, grants no private read, and unlink retains both originals", and the four typed coreference doors plus PPR-only vault.search.hybrid already exist, but no grant-authorized public Connect PERSON-share/import path can bring the foreign PERSON across the current Connect grant, so R3-federation-018 — a confirmed cross-vault identity link never pools claims through PPR in either stored orientation or traversal direction, proven with a positive PPR control in each direction — must be asserted inside this case via PPR-only vault.search.hybrid once that door exists, because light recall never runs PPR and cannot prove it. */
suite.todo(test, "FEDERATION-05", "waits on a grant-authorized public Connect PERSON-share/import path: named-world claims can arrive, but their subject PERSON cannot be brought across by the current Connect grant; the typed coreference and PPR-only search doors already exist.");

// FEDERATION-06 — Disconnect stale content and courtesy deletion should work.
// OF-159/273; ARCH-0043#relationship-lifecycle; ARCH-0040#federation-admission.
/* Promise: a recipient-local disconnect hides a retained foreign claim from normal recall but exposes its stale stamp under explicit scope; a real peer courtesy request can be declined without restoring access.
 * Doors: none driven; the case stays suite.todo.
 * Unproved: the whole promise. The partial promise is blocked by timing alone: vault.courtesy_delete.send only queues, the courier runs on the 60s housekeeping tick, and no public flush door exists behind any grant, so no dependable sub-30s bound exists for the courtesy leg with the allowed starts plus restart (a sender restart may trigger an immediate first tick, but that timing is unmeasured and not guaranteed). Authenticated peer disconnect admission and Connect discarded-unsynced-edit reporting are full-title-only gaps.
 */
suite.todo(test, "FEDERATION-06", "waits on a grant-authorized bounded courtesy outbox delivery wake or flush (send only queues; the courier runs on the 60s housekeeping tick), authenticated peer disconnect admission, and Connect discarded-unsynced-edit reporting");

// FEDERATION-07 — Peer anomaly quarantines without losing review should work.
// OF-152/303; ARCH-0023b#decision-federation-26; ARCH-0040#mcp-actor-ceilings.
type Fed07Scope = FacadeInput<"vault.federation.connect.grants.mint">["authority_scope"];
type Fed07Direction = FacadeInput<"vault.federation.connect.offer">["outbound"];
type Fed07Peer = FacadeInput<"vault.federation.burst.policy">;
type Fed07Evidence = FacadeResult<"vault.consolidation.evidence">["value"][number];
type Fed07SourceTrust = NonNullable<FacadeInput<"vault.gate.policy.put">["manifest"]["source_trust"]>[string];
interface Fed07Fixture {
  readonly cases: readonly {
    readonly id: string;
    readonly inputs: {
      readonly ordinaryBatch?: readonly string[];
      readonly anomalousBatch?: readonly string[];
      readonly configuredRoutes?: readonly string[];
    };
    readonly expected: {
      readonly oracle?: string;
      readonly isolationReviewBundleCount?: number;
      readonly deferredWorkLost?: boolean;
      readonly deferredReplayPreserves?: readonly string[];
    };
  }[];
}
interface Fed07Pact {
  readonly pact: string;
  readonly sharerVault: string;
  readonly receiverVault: string;
  readonly sharerWorld: string;
  readonly receiverWorld: string;
  readonly receiverGrant: FacadeResult<"vault.federation.connect.grants.mint">;
}

const FED07_PREDICATE = "federation.fixture.document";
const FED07_ALLOW_TS = 1757937600;
const FED07_ISOLATE_TS = 1760529600;
const FED07_DEFER_TS = 1763208000;

function fed07ShareScope(world: string): Fed07Scope {
  return {
    worlds: { kind: "some", values: [world] },
    facets: { kind: "all" },
    bands: { kind: "all" },
    audience: { kind: "all" },
    verbs: { kind: "some", values: ["read"] },
    sensitivity: { kind: "at_most", value: "private" },
  };
}
function fed07Direction(world: string): Fed07Direction {
  return {
    worlds: { kind: "some", values: [world] },
    facets: { kind: "all" },
    bands: { kind: "all" },
  };
}
function fed07WindowKey(learnedAt: number, world: string): string {
  return `${new Date(learnedAt * 1000).toISOString().slice(0, 7)}@${world}`;
}
async function fed07Refusal(attempt: Promise<unknown>, engine: EngineFixture): Promise<PublicHttpError> {
  try {
    await attempt;
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    const receiptRef = error.reply.headers.get("x-oneiron-receipt-ref");
    expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
    if (!receiptRef) throw new Error("Authenticated refusal has no call receipt");
    expect(error.error?.receiptRef).toBe(receiptRef);
    const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
    if (!receipt) throw new Error("Refusal receipt was not readable by the owner");
    expect(receipt.receipt_ref).toBe(receiptRef);
    expect(receipt.transport).toBe("http_facade");
    const refusedCode = error.error?.code;
    if (!refusedCode) throw new Error("Refusal carries no error code");
    expect(receipt.outcome).toEqual({ refused: { code: refusedCode } });
    return error;
  }
  throw new Error("expected a public refusal; the call succeeded");
}
async function fed07NamedWorld(engine: EngineFixture, name: string, occurred: number): Promise<string> {
  const world = await engine.client.call("vault.structural.put", {
    kind: "WORLD",
    body: { name, kind: "fictional" },
    occurred_at: occurred,
    text_fields: [{ field: "name", value: name }],
  });
  expect(world.id_hex).toMatch(/^[a-f0-9]{32}$/);
  expect(world.entity_ref.length).toBeGreaterThan(0);
  const read = await engine.client.call("vault.get", { entity_ref: world.entity_ref });
  if (!read.value) throw new Error("Created WORLD is not publicly readable");
  expect(read.value.kind).toBe("WORLD");
  expect(read.value.id_hex).toBe(world.id_hex);
  expect(read.value.body).toMatchObject({ name, kind: "fictional" });
  return world.id_hex;
}
async function fed07ConnectPact(sharer: EngineFixture, receiver: EngineFixture): Promise<Fed07Pact> {
  const [sharerId, receiverId] = await Promise.all([
    sharer.client.call("vault.federation.connect.identity", {}),
    receiver.client.call("vault.federation.connect.identity", {}),
  ]);
  expect(sharerId.vault).not.toBe(receiverId.vault);
  expect(sharerId.vault).toMatch(/^[a-f0-9]{64}$/);
  expect(receiverId.vault).toMatch(/^[a-f0-9]{64}$/);
  const [sharerWorld, receiverWorld] = await Promise.all([
    fed07NamedWorld(sharer, "FED-07 shared workshop", FED07_ALLOW_TS),
    fed07NamedWorld(receiver, "FED-07 receiving workshop", FED07_ALLOW_TS),
  ]);
  expect(sharerWorld).not.toBe(receiverWorld);
  const [sharerGrant, receiverGrant] = await Promise.all([
    sharer.client.call("vault.federation.connect.grants.mint", {
      peer_vault: receiverId.vault,
      authority_scope: fed07ShareScope(sharerWorld),
    }),
    receiver.client.call("vault.federation.connect.grants.mint", {
      peer_vault: sharerId.vault,
      authority_scope: fed07ShareScope(receiverWorld),
    }),
  ]);
  expect(sharerGrant.grant).toMatch(/^[a-f0-9]{32}$/);
  expect(receiverGrant.grant).toMatch(/^[a-f0-9]{32}$/);
  expect(sharerGrant.guest_actor).toMatch(/^[a-f0-9]{32}$/);
  expect(receiverGrant.guest_actor).toMatch(/^[a-f0-9]{32}$/);
  const offer = await sharer.client.call("vault.federation.connect.offer", {
    peer_vault: receiverId.vault,
    grant: sharerGrant.grant,
    outbound: fed07Direction(sharerWorld),
    inbound: fed07Direction(receiverWorld),
  });
  const receiverAccepted = await receiver.client.call("vault.federation.connect.accept", {
    offer,
    grant: receiverGrant.grant,
  });
  expect(receiverAccepted.pact).toBe(offer.pact);
  expect(receiverAccepted.status).toBe("Active");
  const sharerAccepted = await sharer.client.call("vault.federation.connect.accept", {
    offer: receiverAccepted.counter,
    grant: sharerGrant.grant,
  });
  expect(sharerAccepted.pact).toBe(offer.pact);
  expect(sharerAccepted.status).toBe("Active");
  const [sharerStatus, receiverStatus] = await Promise.all([
    sharer.client.call("vault.federation.status", {}),
    receiver.client.call("vault.federation.status", {}),
  ]);
  for (const status of [sharerStatus, receiverStatus]) {
    const active = status.pacts.find((row) => row.pact === offer.pact);
    expect(active?.status).toBe("Active");
    expect(active?.epoch).toBe(1);
  }
  return {
    pact: offer.pact,
    sharerVault: sharerId.vault,
    receiverVault: receiverId.vault,
    sharerWorld,
    receiverWorld,
    receiverGrant,
  };
}
async function fed07Evidence(engine: EngineFixture, claimRef: string): Promise<Fed07Evidence> {
  const read = await engine.client.call("vault.consolidation.evidence", { source_refs: [claimRef] });
  expect(read.value).toHaveLength(1);
  const row = read.value[0];
  if (!row) throw new Error(`No evidence row for ${claimRef}`);
  return row;
}

/* Promise: a peer's authorized batches follow the configured allow, isolate-and-propose, or defer route; review survives, and released/deferred work replays idempotently across restart with foreign provenance.
 * Doors: vault.get, vault.receipts.get, vault.federation.status, vault.structural.put, vault.federation.connect.identity/grants.mint/offer/accept/export, vault.gate.policy.get/put, vault.federation.burst.policy/policy.set/disposition/review/review.release/replay/ingress, vault.claims.upsert/list, vault.consolidation.evidence, self.credential.attenuate, vault.guests.revoke, restart.
 * Unproved: bundle reject path not driven; vault.federation.burst.review.reject is available behind owner proof.
 * Unproved: unaffected second peer on same receiver not driven; needs real C grant/pact/content behind Connect grants, three-server cost unmeasured.
 * Unproved: maintenance per-peer byte/window quota not driven; needs public maintenance quota policy get/set plus receipted admission verb behind owner/peer grants.
 * Unproved: raw sync ACK not observed; needs caller-owned raw sync client binding real peer/grant behind peer grant.
 * Unproved: unusual_streak branch not triggered; needs public authorized ingress of genuinely malformed structural work with receipted disposition behind owner/peer grants.
 * Unproved: expired/stale_authority/erased transitions not driven; no universal clock door asserted, runtime scheduling unproved.
 * Unproved: same burst under distinct baselines/vault sizes not compared; needs independent receiving authority contexts behind Connect grants, not defeating idempotency.
 */
suite.test(test, "FEDERATION-07", "A peer's authorized batches follow the configured allow, isolate-and-propose, or defer route; review survives, and released/deferred work replays idempotently across restart with foreign provenance.", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Fed07Fixture>("federation-canon-scenarios");
  const scenario = data.cases.find((row) => row.id === "FEDERATION-07");
  if (!scenario) throw new Error("federation-canon-scenarios has no FEDERATION-07");
  const ordinary = scenario.inputs.ordinaryBatch?.[0];
  const anomalous = scenario.inputs.anomalousBatch?.[0];
  if (typeof ordinary !== "string" || typeof anomalous !== "string") throw new Error("FEDERATION-07 fixture has no ordinary/anomalous batch");
  expect(scenario.inputs.configuredRoutes).toContain("allow");
  expect(scenario.inputs.configuredRoutes).toContain("isolate-and-propose");
  expect(scenario.inputs.configuredRoutes).toContain("defer");
  expect(scenario.expected.oracle).toBe("configured_routed_outcome_and_receipt");
  expect(scenario.expected.isolationReviewBundleCount).toBe(1);
  expect(scenario.expected.deferredWorkLost).toBe(false);
  const deferredValue = `${ordinary} Deferred.`;
  const engine = await EngineFixture.start({ id: "FEDERATION-07", profile, peers: 1 });
  try {
    const receiver = engine.peers[0];
    if (!receiver) throw new Error("FEDERATION-07 needs its peer vault");
    const pact = await fed07ConnectPact(engine, receiver);
    const scopeA = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const policy = await receiver.client.call("vault.gate.policy.get", {});
    const manifest = policy.manifests.find((row) => row.manifest_ref === policy.default_manifest_ref);
    if (!manifest) throw new Error("Receiving vault has no default policy manifest");
    const permit: Fed07SourceTrust = { max_auto_sensitivity: 1, receipted: true, warned: true };
    const put = await receiver.client.call("vault.gate.policy.put", {
      manifest_ref: manifest.manifest_ref,
      expected_body_hash: manifest.body_hash,
      manifest: { ...manifest.manifest, source_trust: { ...(manifest.manifest.source_trust ?? {}), imported: permit } },
    });
    expect(put.receipt_ref.length).toBeGreaterThan(0);
    const permitted = await receiver.client.call("vault.gate.policy.get", {});
    const installedManifest = permitted.manifests.find((row) => row.manifest_ref === manifest.manifest_ref);
    if (!installedManifest) throw new Error("Installed Gate policy is not publicly readable");
    expect(installedManifest.manifest_ref).toBe(put.manifest.manifest_ref);
    expect(installedManifest.body_hash).toBe(put.manifest.body_hash);
    expect(installedManifest.manifest.source_trust?.["imported"]).toEqual(permit);
    const peer: Fed07Peer = {
      principal: pact.receiverGrant.guest_actor,
      grant: pact.receiverGrant.grant,
      scope: { kind: "connect", peer_vault_id: pact.sharerVault },
      world: { kind: "world", world_ref: pact.receiverWorld },
      facets: [],
      bands: [],
    };
    const allowBaseline = { name: "federation-ordinary-baseline", writes_per_sec: 1000000000, structural_streak: 1000000000 };
    await receiver.client.call("vault.federation.burst.policy.set", {
      peer,
      policy: { baseline: allowBaseline, unusual_rate: "allow", unusual_streak: "allow" },
    });
    expect(await receiver.client.call("vault.federation.burst.policy", peer)).toEqual({
      baseline: allowBaseline, unusual_rate: "allow", unusual_streak: "allow",
    });
    const allowWindow = fed07WindowKey(FED07_ALLOW_TS, pact.sharerWorld);
    const allowUpsert = await engine.client.call("vault.claims.upsert", {
      predicate: FED07_PREDICATE,
      subject_ref: engine.pairedActor.principalRef,
      value: ordinary,
      confidence: 0.9,
      source: "user_stated",
      sensitivity: 1,
      scope: { ...scopeA, world_id: pact.sharerWorld },
      occurred_at: FED07_ALLOW_TS,
      learned_at: FED07_ALLOW_TS,
    });
    // Explicit sensitivity requests Proposed; the peer burst route is asserted by allowReceipt below.
    expect(allowUpsert.approval).toBe("proposed");
    const allowDelivery = await engine.client.call("vault.federation.connect.export", {
      pact: pact.pact,
      window_key: allowWindow,
      world_ref: pact.sharerWorld,
    });
    expect(allowDelivery.body.pact).toBe(pact.pact);
    expect(allowDelivery.body.epoch).toBe(1);
    expect(allowDelivery.body.source_vault).toBe(pact.sharerVault);
    expect(allowDelivery.body.recipient_vault).toBe(pact.receiverVault);
    expect(allowDelivery.body.update.length).toBeGreaterThan(0);
    const allowReceipt = await receiver.client.call("vault.federation.burst.ingress", allowDelivery);
    expect(allowReceipt.batch_ref).toMatch(/^[a-f0-9]{64}$/);
    expect(allowReceipt.principal).toBe(pact.receiverGrant.guest_actor);
    expect(allowReceipt.grant).toBe(pact.receiverGrant.grant);
    expect(allowReceipt.window_key).toBe(allowWindow);
    expect(allowReceipt.disposition).toEqual({ outcome: "allow" });
    expect(allowReceipt.state).toBe("imported");
    expect(allowReceipt.baseline.baseline.name).toBe(allowBaseline.name);
    expect(allowReceipt.baseline.learned).toBe(false);
    expect(allowReceipt.baseline.vault_size).toBeGreaterThan(0);
    const allowList = await awaitPublic(
      () => receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 }),
      (page) => page.value.some((row) => row.value === ordinary),
      { label: "allowed foreign claim readable" },
    );
    expect(allowList.value).toHaveLength(1);
    const allowRow = allowList.value[0];
    if (!allowRow) throw new Error("Allowed claim missing");
    expect(allowRow.value).toBe(ordinary);
    expect(allowRow.source).toBe("imported");
    expect(allowRow.lifecycle).toBe("active");
    const foreignWorld = allowRow.world_ref;
    if (typeof foreignWorld !== "string") throw new Error("Allowed claim has no foreign world");
    expect(foreignWorld).not.toBe(pact.sharerWorld);
    expect(foreignWorld).not.toBe(pact.receiverWorld);
    expect(foreignWorld).not.toBe("00000000000000000000000000000001");
    const isolateBaseline = { name: "federation-burst-isolate", writes_per_sec: 0.000000001, structural_streak: 1000000000 };
    await receiver.client.call("vault.federation.burst.policy.set", {
      peer,
      policy: { baseline: isolateBaseline, unusual_rate: "isolate-and-propose", unusual_streak: "defer" },
    });
    expect(await receiver.client.call("vault.federation.burst.policy", peer)).toEqual({
      baseline: isolateBaseline, unusual_rate: "isolate-and-propose", unusual_streak: "defer",
    });
    const isolateWindow = fed07WindowKey(FED07_ISOLATE_TS, pact.sharerWorld);
    await engine.client.call("vault.claims.upsert", {
      predicate: FED07_PREDICATE,
      subject_ref: pact.sharerWorld,
      value: anomalous,
      confidence: 0.9,
      source: "user_stated",
      sensitivity: 1,
      scope: { ...scopeA, world_id: pact.sharerWorld },
      occurred_at: FED07_ISOLATE_TS,
      learned_at: FED07_ISOLATE_TS,
    });
    const isolateDelivery = await engine.client.call("vault.federation.connect.export", {
      pact: pact.pact,
      window_key: isolateWindow,
      world_ref: pact.sharerWorld,
    });
    expect(isolateDelivery.body.pact).toBe(pact.pact);
    expect(isolateDelivery.body.epoch).toBe(1);
    expect(isolateDelivery.body.source_vault).toBe(pact.sharerVault);
    expect(isolateDelivery.body.recipient_vault).toBe(pact.receiverVault);
    expect(isolateDelivery.body.update.length).toBeGreaterThan(0);
    const isolateReceipt = await receiver.client.call("vault.federation.burst.ingress", isolateDelivery);
    expect(isolateReceipt.batch_ref).toMatch(/^[a-f0-9]{64}$/);
    expect(isolateReceipt.window_key).toBe(isolateWindow);
    expect(isolateReceipt.state).toBe("pending");
    expect(isolateReceipt.baseline.baseline.name).toBe(isolateBaseline.name);
    const isolateDisp = isolateReceipt.disposition;
    if (isolateDisp.outcome !== "isolate-and-propose") throw new Error("Isolate batch did not take the isolate route");
    expect(isolateDisp.bundle_ref).toMatch(/^federation-review:[a-f0-9]{64}$/);
    expect(isolateDisp.replay_ref).toBe(isolateReceipt.batch_ref);
    const isolatedReview = await receiver.client.call("vault.federation.burst.review", {});
    expect(isolatedReview).toHaveLength(1);
    const isolatedBundle = isolatedReview[0];
    if (!isolatedBundle) throw new Error("Isolated review bundle missing");
    expect(isolatedBundle.bundle_ref).toBe(isolateDisp.bundle_ref);
    expect(isolatedBundle.request_refs).toContain(isolateReceipt.batch_ref);
    expect(isolatedBundle.updates.length).toBeGreaterThan(0);
    expect(isolatedBundle.quarantined).toBe(true);
    expect(isolatedBundle.replay_automatic).toBe(true);
    const isolatedUpdate = isolatedBundle.updates[0];
    if (!isolatedUpdate) throw new Error("Isolated bundle has no update");
    expect(isolatedUpdate.request_ref).toBe(isolateReceipt.batch_ref);
    const heldList = await receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 });
    expect(heldList.value.map((row) => row.value)).not.toContain(anomalous);
    expect(heldList.value).toHaveLength(1);
    const released = await receiver.client.call("vault.federation.burst.review.release", { bundle_ref: isolatedBundle.bundle_ref });
    expect(released.bundle_ref).toBe(isolatedBundle.bundle_ref);
    expect(released.batches).toHaveLength(1);
    const releasedBatch = released.batches[0];
    if (!releasedBatch) throw new Error("Release returned no batch");
    expect(releasedBatch.batch_ref).toBe(isolateReceipt.batch_ref);
    expect(releasedBatch.state).toBe("pending");
    expect(releasedBatch.disposition.outcome).toBe("isolate-and-propose");
    const isolateReplayed = await receiver.client.call("vault.federation.burst.replay", { peer, batch_ref: isolateReceipt.batch_ref });
    expect(isolateReplayed.batch_ref).toBe(isolateReceipt.batch_ref);
    expect(isolateReplayed.state).toBe("imported");
    expect(isolateReplayed.disposition.outcome).toBe("isolate-and-propose");
    const isolateDispAfter = isolateReplayed.disposition;
    if (isolateDispAfter.outcome !== "isolate-and-propose") throw new Error("Released receipt lost its original disposition");
    expect(isolateDispAfter.bundle_ref).toBe(isolateDisp.bundle_ref);
    expect(isolateDispAfter.replay_ref).toBe(isolateReceipt.batch_ref);
    const releasedList = await awaitPublic(
      () => receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 }),
      (page) => page.value.some((row) => row.value === anomalous),
      { label: "released claim readable" },
    );
    expect(releasedList.value).toHaveLength(2);
    const releasedRow = releasedList.value.find((row) => row.value === anomalous);
    if (!releasedRow) throw new Error("Released claim missing");
    expect(releasedRow.source).toBe("imported");
    expect(releasedRow.world_ref).toBe(foreignWorld);
    const releasedEvidence = await fed07Evidence(receiver, releasedRow.claim_ref);
    expect(releasedEvidence.source).toBe("imported");
    expect(releasedEvidence.foreign_world_ref).toBe(foreignWorld);
    expect(releasedEvidence.first_party_corroboration).toBe(false);
    expect(releasedEvidence.writer_ref).not.toBe(receiver.pairedActor.principalRef);
    expect(releasedEvidence.delivery_history).toHaveLength(1);
    const releasedOrigin = releasedEvidence.delivery_history?.[0];
    if (!releasedOrigin) throw new Error("Released claim has no delivery origin");
    expect(releasedOrigin.source_ref).toBe(releasedRow.claim_ref);
    expect(releasedOrigin.delivering_pact).toBe(pact.pact);
    expect(releasedOrigin.consent_epoch).toBe(1);
    expect(releasedOrigin.grant_ref).toBe(pact.receiverGrant.grant);
    expect(releasedOrigin.source_vault).toBe(pact.sharerVault);
    expect(releasedOrigin.delivered_row_hash).toMatch(/^[a-f0-9]{64}$/);
    const deferBaseline = { name: "federation-burst-defer", writes_per_sec: 0.000000001, structural_streak: 1000000000 };
    await receiver.client.call("vault.federation.burst.policy.set", {
      peer,
      policy: { baseline: deferBaseline, unusual_rate: "defer", unusual_streak: "isolate-and-propose" },
    });
    expect(await receiver.client.call("vault.federation.burst.policy", peer)).toEqual({
      baseline: deferBaseline, unusual_rate: "defer", unusual_streak: "isolate-and-propose",
    });
    const deferWindow = fed07WindowKey(FED07_DEFER_TS, pact.sharerWorld);
    await engine.client.call("vault.claims.upsert", {
      predicate: FED07_PREDICATE,
      subject_ref: scopeA.scope_facet_id,
      value: deferredValue,
      confidence: 0.9,
      source: "user_stated",
      sensitivity: 1,
      scope: { ...scopeA, world_id: pact.sharerWorld },
      occurred_at: FED07_DEFER_TS,
      learned_at: FED07_DEFER_TS,
    });
    const deferDelivery = await engine.client.call("vault.federation.connect.export", {
      pact: pact.pact,
      window_key: deferWindow,
      world_ref: pact.sharerWorld,
    });
    expect(deferDelivery.body.pact).toBe(pact.pact);
    expect(deferDelivery.body.epoch).toBe(1);
    expect(deferDelivery.body.source_vault).toBe(pact.sharerVault);
    expect(deferDelivery.body.recipient_vault).toBe(pact.receiverVault);
    expect(deferDelivery.body.update.length).toBeGreaterThan(0);
    const deferReceipt = await receiver.client.call("vault.federation.burst.ingress", deferDelivery);
    expect(deferReceipt.batch_ref).toMatch(/^[a-f0-9]{64}$/);
    expect(deferReceipt.window_key).toBe(deferWindow);
    expect(deferReceipt.state).toBe("pending");
    expect(deferReceipt.baseline.baseline.name).toBe(deferBaseline.name);
    const deferDisp = deferReceipt.disposition;
    if (deferDisp.outcome !== "defer") throw new Error("Defer batch did not take the defer route");
    expect(deferDisp.replay_ref).toBe(deferReceipt.batch_ref);
    const deferredHeld = await receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 });
    expect(deferredHeld.value.map((row) => row.value)).not.toContain(deferredValue);
    expect(deferredHeld.value).toHaveLength(2);
    await receiver.restart();
    const restored = await receiver.client.call("vault.federation.burst.disposition", { peer, batch_ref: deferReceipt.batch_ref });
    expect(restored.batch_ref).toBe(deferReceipt.batch_ref);
    expect(restored.principal).toBe(pact.receiverGrant.guest_actor);
    expect(restored.grant).toBe(pact.receiverGrant.grant);
    expect(restored.window_key).toBe(deferWindow);
    expect(restored.state).toBe("pending");
    expect(restored.disposition.outcome).toBe("defer");
    expect(restored.baseline.baseline.name).toBe(deferBaseline.name);
    const reviewAfterRestart = await receiver.client.call("vault.federation.burst.review", {});
    expect(reviewAfterRestart).toHaveLength(1);
    const surviving = reviewAfterRestart[0];
    if (!surviving) throw new Error("Review bundle did not survive restart");
    expect(surviving.bundle_ref).toBe(isolatedBundle.bundle_ref);
    expect(surviving.request_refs).toContain(isolateReceipt.batch_ref);
    expect(surviving.quarantined).toBe(false);
    expect(surviving.replay_automatic).toBe(true);
    const releasedAgain = await receiver.client.call("vault.federation.burst.replay", { peer, batch_ref: isolateReceipt.batch_ref });
    expect(releasedAgain.batch_ref).toBe(isolateReceipt.batch_ref);
    expect(releasedAgain.state).toBe("imported");
    expect(releasedAgain.disposition).toEqual(isolateReceipt.disposition);
    const firstReplay = await receiver.client.call("vault.federation.burst.replay", { peer, batch_ref: deferReceipt.batch_ref });
    expect(firstReplay.batch_ref).toBe(deferReceipt.batch_ref);
    expect(firstReplay.state).toBe("imported");
    expect(firstReplay.disposition.outcome).toBe("defer");
    const secondReplay = await receiver.client.call("vault.federation.burst.replay", { peer, batch_ref: deferReceipt.batch_ref });
    expect(secondReplay.batch_ref).toBe(deferReceipt.batch_ref);
    expect(secondReplay.state).toBe("imported");
    expect(secondReplay.disposition.outcome).toBe("defer");
    const deferredList = await awaitPublic(
      () => receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 }),
      (page) => page.value.some((row) => row.value === deferredValue),
      { label: "deferred claim readable after replay" },
    );
    expect(deferredList.value).toHaveLength(3);
    const releasedRowAfterRestart = deferredList.value.find((row) => row.value === anomalous);
    if (!releasedRowAfterRestart) throw new Error("Released claim missing after restart replay");
    expect(releasedRowAfterRestart.claim_ref).toBe(releasedRow.claim_ref);
    expect(releasedRowAfterRestart.source).toBe("imported");
    expect(releasedRowAfterRestart.world_ref).toBe(foreignWorld);
    const releasedEvidenceAfterRestart = await fed07Evidence(receiver, releasedRowAfterRestart.claim_ref);
    expect(releasedEvidenceAfterRestart.source).toBe("imported");
    expect(releasedEvidenceAfterRestart.foreign_world_ref).toBe(foreignWorld);
    expect(releasedEvidenceAfterRestart.first_party_corroboration).toBe(false);
    expect(releasedEvidenceAfterRestart.writer_ref).toBe(releasedEvidence.writer_ref);
    expect(releasedEvidenceAfterRestart.delivery_history).toHaveLength(1);
    expect(releasedEvidenceAfterRestart.delivery_history).toEqual(releasedEvidence.delivery_history);
    const deferredRow = deferredList.value.find((row) => row.value === deferredValue);
    if (!deferredRow) throw new Error("Deferred claim missing after replay");
    expect(deferredRow.source).toBe("imported");
    expect(deferredRow.world_ref).toBe(foreignWorld);
    const deferredEvidence = await fed07Evidence(receiver, deferredRow.claim_ref);
    expect(deferredEvidence.source).toBe("imported");
    expect(deferredEvidence.foreign_world_ref).toBe(foreignWorld);
    expect(deferredEvidence.first_party_corroboration).toBe(false);
    expect(deferredEvidence.writer_ref).not.toBe(receiver.pairedActor.principalRef);
    expect(deferredEvidence.delivery_history).toHaveLength(1);
    const deferredOrigin = deferredEvidence.delivery_history?.[0];
    if (!deferredOrigin) throw new Error("Deferred claim has no delivery origin");
    expect(deferredOrigin.source_ref).toBe(deferredRow.claim_ref);
    expect(deferredOrigin.delivering_pact).toBe(pact.pact);
    expect(deferredOrigin.consent_epoch).toBe(1);
    expect(deferredOrigin.grant_ref).toBe(pact.receiverGrant.grant);
    expect(deferredOrigin.source_vault).toBe(pact.sharerVault);
    expect(deferredOrigin.delivered_row_hash).toMatch(/^[a-f0-9]{64}$/);
    const { seed } = credentialParts(receiver.pairedActor.credential);
    const narrowed = await receiver.client.call("self.credential.attenuate", {
      holder_seed: [...Buffer.from(seed, "hex")],
      caveat: {
        scope: {
          kind: "ceiling",
          scope: {
            worlds: { kind: "all" },
            facets: { kind: "all" },
            bands: { kind: "all" },
            audience: { kind: "all" },
            verbs: { kind: "some", values: ["core:read"] },
            sensitivity: { kind: "all" },
          },
        },
      },
    });
    expect(narrowed.token.startsWith("v2.slip.")).toBe(true);
    const weak = new PublicHttpClient(receiver.url, {
      credential: `v2.cred.${narrowed.token.slice(8)}.${seed}`,
      artifacts: receiver.artifacts,
    });
    const weakRefused = await fed07Refusal(weak.call("vault.federation.burst.policy", peer), receiver);
    expect(weakRefused.reply.status).toBe(403);
    expect(weakRefused.error?.code).toBe("FORBIDDEN");
    const revoked = await receiver.client.call("vault.guests.revoke", { grant_ref: pact.receiverGrant.grant });
    expect(revoked.grant_ref).toBe(pact.receiverGrant.grant);
    expect(revoked.guest_ref).toBe(pact.receiverGrant.guest_actor);
    expect(revoked.changed).toBe(true);
    expect(revoked.pact_standing).toBe("disconnected");
    expect(revoked.disclosure.copied_bytes_recallable).toBe(false);
    expect(revoked.disclosure.recipient_copy_state).toBe("unknown");
    expect(revoked.disclosure.deletion_request_status).toBe("not_requested");
    const standing = await receiver.client.call("vault.federation.status", {});
    expect(standing.pacts.find((row) => row.pact === pact.pact)?.status).toBe("Disconnected");
    const replayLost = await fed07Refusal(receiver.client.call("vault.federation.burst.replay", { peer, batch_ref: deferReceipt.batch_ref }), receiver);
    expect(replayLost.reply.status).toBe(400);
    expect(replayLost.error?.code).toBe("BAD_REQUEST");
    const finalList = await receiver.client.call("vault.claims.list", { predicate: FED07_PREDICATE, limit: 100 });
    expect(finalList.value).toHaveLength(3);
    expect(finalList.value.find((row) => row.value === anomalous)?.claim_ref).toBe(releasedRow.claim_ref);
    expect(finalList.value.find((row) => row.value === deferredValue)?.claim_ref).toBe(deferredRow.claim_ref);
    expect(finalList.value.map((row) => row.value).sort()).toEqual([ordinary, anomalous, deferredValue].sort());
  } finally {
    await engine.close();
  }
});

// FEDERATION-08 — Hosting trust modes stay explicit should work.
// OF-040/162/168/275/292; identity#cloud-agent-recovery.
// Required declaration contract: configured mode managed|self-host|relay,
// authority-root holder, host readability/key custody and recovery route.
// Local managed host adapter: root is its trusted host, owner action lands
// through host authority, read/propose alone never widens. Self-host adapter:
// root is the owner's box. Relay adapter: no engine/key/root, no authority
// mint, even if a proposal or ciphertext claims one. Relay mode's ENGINE lives
// on owner devices; do not launch serve in relay posture as a blind relay.
// Inspect the declarations and behavior of all three, not just CLI --help.
// Built CLI: host relay --config <file>; host recover-shared-owner --vault-id
// <decimal> --from <person> --claimant <person> --proof-note <note> --config
// <file> on a STOPPED self-host vault. Live operator alternative exists:
// POST /v1/operator/shared/recover-owner {vault_id,from,claimant,proof_note}
// -> SharedActExecutionReceipt; a member/owner slip is not the host operator.
// Recovery must restore only that vault's signing/access, with no ceiling
// raise. No cloud-as-member ceremony, owner-device-key quorum or SetTierFloor
// requirement may be introduced to make any fixture open. Current authority
// audit rows can diagnose host genesis, but are not a hosting declaration.
// Missing: typed public root/privacy declaration and prepared local managed/
// relay host adapter lifecycle. EngineFixture starts self-host engine vaults;
// it must not be reinterpreted as all three modes or an operator credential.
// Do not treat recovery's existing CLI/HTTP door itself as missing, nor make
// an app-tier SDK grant operator power merely to unblock this test.
suite.todo(test, "FEDERATION-08", "waits on typed hosting root/privacy declaration and local managed/relay host fixtures");
