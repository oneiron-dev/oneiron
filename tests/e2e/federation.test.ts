import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

// Binding readback: main 0dcb431bb50d39b01d7bc222e2d28922bf59bc4d.
// Checked the generated HTTP/JS catalogs, OpenAPI registration/owner paths,
// org_admin routes and CLI. Runtime OpenAPI remains a diagnostic, not an oracle.
// Fixtures: federation-canon-scenarios, fixtures/federation/scenarios.json.
// Source pins and independent expected facts are in the hash-checked fixture.
// Labels below name future public fixtures, not pre-seeded engine records.
//
// G01: these are full-flow blockers, not passing partial tests. suite.todo uses
// Bun test.todo and emits BLOCKED, including for a registration-only file.
// Existing typed calls are documented below so an implementer does not replace
// them or mistake a missing follow-on verb for an absent whole subsystem.
// Required contracts describe canon's data, NOT newly invented callable names.
// No generic facade casts, batch/structural authority writes, private signing,
// fake vaults, or internal admission/replay calls stand in for missing doors.

// FEDERATION-01 — Member and admin powers should work.
// OF-150/158/157/287/331; ARCH-0043#shared-vault-authority.
// Setup: host shared vault; two equal Owners; Admin, Member, Viewer and an
// expiring Delegate; a disjoint guest grant; guest/third vaults and a separate
// personal root containing the fixture's private sentence.
// Available typed setup: vault.shape.plan({preset:{preset:"org",vault_id,
// members:[{member,role}]}}) -> ShapePlan; vault.shape.apply({plan,approve}) ->
// ShapeApplyReceipt. ShapeMemberRole is owner|admin|member|viewer, not guest.
// Membership calls: vault.members.add({vault_id,member,role?,holder_key?}) ->
// {receipt,credential?}; accept({vault_id,invitation}) -> receipt;
// change({vault_id,member,role}) / remove({vault_id,member}) -> receipt.
// GET /v1/core/org-admin/{org}/powers -> {powers:string[]} exists, as does
// owner-only POST .../policy. Neither is a generated typed SDK operation.
// Required contracts: named Admin powers and a bounded Delegate grant (parent,
// holder, scope, expiry, no onward delegation), plus a role/person/relationship
// projection. A guest must not be inserted as a member to manufacture setup.
// Journey: Admin adds/removes a member, changes a role, resets project access;
// exercise each other role's allowed read/write and refused widen. Attempt
// Admin self-grant/root mutation, Owner objection and personal-vault reads.
// Attempt Delegate onward grant and use after its public expiry boundary.
// Read the projection as two actors: roles/person/relationship agree, but the
// label confers no extra power. Assert exact named-power sets, no private
// sentence in Admin recall, and no personal-root change after shared removal.
// Missing: typed named-power/reset-project-access and scoped Delegate grant
// doors/projection. Shape setup and ordinary membership alone cover less than
// this ID; do not seed OrgAdminPolicy or FederationGrant through Rust/batch.
suite.todo(test, "FEDERATION-01", "waits on typed named Admin powers, scoped Delegate grants and relationship-role projection");

// FEDERATION-02 — Owner veto window should work.
// OF-163; ARCH-0043#shared-vault-authority; identity#cloud-agent-recovery.
// Two live Owners, with a third initially present then no longer live, govern
// each independent destructive fixture. Inspect the default before configuring
// the short fixture wait: four acts, 604800 seconds each; export is absent.
// Available: vault.shared.propose_delete({vault_id}),
// propose_transfer({vault_id,to,from_keeps?}),
// propose_remove_owner({vault_id,target,successor?,target_keeps?,export_first})
// -> PendingAuthorityAct {id,vault_id,act,starter,started_at,deadline,
// objector_roles,objections,completed,execution?};
// object/withdraw_objection/execute({act_id}); started/matured({vault_id}) ->
// notices {act_id,vault_id,act,recipient,deadline,...}; receipt({receipt_id}).
// Erase uses vault.records.erase_preview({record}) -> {preview_digest,...},
// then erase_confirm({record,preview_digest}) -> {first,first_act?,same_bytes}.
// Required policy contract: read the act list/waits and jointly authorize a
// change by exactly the live Owners. Use wait_secs=2 only as explicit fixture
// policy, never a new engine default, caller clock, or private queue advance.
// For EACH of delete-vault/erase/transfer/remove-Owner: start, assert deadline
// and the other Owner's typed notice, object before expiry, await the public
// matured boundary, attempt execution and assert the act remains held with
// no destructive effect. Admin cannot object. Withdraw only with the live
// Owners' agreement; removed/dead holders neither release nor hold it forever.
// Await the real execution receipt, not just completed=true. For remove-Owner,
// cover export_first true/false and last-Owner successor/self-removal. Ordinary
// Owner export must be immediate with a receipt all Owners can see, not an act
// on the veto list. Do not wait seven real days to establish the default.
// Missing: typed default-policy inspection and all-live-Owner policy editing;
// no SharedActPolicy DTO/call exists in the generated public catalog. A shape
// manifest hex body is not the named typed policy door G01 requires.
suite.todo(test, "FEDERATION-02", "waits on typed shared-act default policy read and all-live-Owner veto policy change");

// FEDERATION-03 — Exact reciprocal relationship consent should work.
// OF-156/167; ARCH-0043#relationship-lifecycle.
// Existing HTTP (no generated typed SDK binding):
// GET /v1/owner/federation/connect -> {vault,host_key};
// POST .../grants {peer_vault,authority_scope,expires_at?} ->
// {grant,guest_actor,resolved_scope,expires_at};
// POST .../offer {peer_vault,grant,outbound,inbound} ->
// {pact,nonce,from,to,scope,signer,signature};
// POST .../accept {offer,grant} -> {pact,status,peer_key,counter}.
// Required follow-on contracts: owner re-scope (pact, disclosed directional
// scopes, epoch and reciprocal owner commitments) -> typed pact/receipt;
// unilateral disconnect (pact) -> both-direction access/sync-stop receipt.
// Start from the two fixture scope proposals that differ on a named world.
// Mismatched reciprocal consent must not activate either direction. Carry the
// hosts' signed matching halves, not locally signed fake authority records,
// and finish both accepts before asserting the permitted two-way flow.
// Narrow without breakup; old excluded content must stop flowing. A wider
// proposal is inert until fresh owner acts on the identical disclosure at a
// new epoch. A bare scope hash is never an acceptable owner commitment:
// hosts make keyed/per-grant-nonce commitments. Empty requested axes do not
// narrow; an empty grant ceiling is explicit bottom, never all. Disconnect one side and
// observe refused future flow BOTH ways, with no need for peer cooperation.
// Missing: typed SDK Connect plus named re-scope/disconnect HTTP+SDK calls.
// vault.guests.revoke is not a substitute for the complete re-scope lifecycle.
suite.todo(test, "FEDERATION-03", "waits on typed SDK Connect and reciprocal re-scope/disconnect calls");

// FEDERATION-04 — Guest share cannot reshare or reveal topology should work.
// OF-141/153/154/069/232; ARCH-0043#guest-grants/#relationship-lifecycle.
// Setup has a shareable host-authored document, another unshared document,
// hidden members, an unrelated edge and unique fixture topology sentinels.
// Required share/envelope contract: a named non-base world/facet/band ceiling,
// accountable guest, read/propose-only actions, epoch and the recipient's
// filtered signed body/update. Inspect the ACTUAL guest WS envelope and its
// decoded authorized content, not a server-generated expected snapshot.
// Assert only the authored document arrives; hidden membership/roster ids,
// topology edges and counts are absent from metadata AND decoded payload.
// Guest cannot widen, join the authority roster, select base or reshare the
// received foreign world to third. A host-authored control share to third
// must work, so a disconnected third is not mistaken for non-transitivity.
// No test claims to prevent an owner manually re-authoring what they saw.
// Available vault.shares.create({recipient,brief_ref,world_refs?,...}) ->
// {share_id,recipient,brief_ref,...} and shares.view({share_ref,narrowing?})
// -> {value,narrowing} are BRIEF shares, not a federation envelope door.
// Available vault.guests.revoke({grant_ref}) -> {grant_ref,guest_ref,changed,
// revoked_at,revoked_slip_refs?,pact_standing,disclosure,courtesy_targets?}.
// After host revocation, future HTTP/WS read/propose must fail and the receipt
// must say disclosure.copied_bytes_recallable=false, recipient_copy_state=
// "unknown"; no successful deletion or deletion attestation is implied.
// Missing: typed guest document share/export-envelope and foreign-world
// reshare operations with SDK bindings. Do not test just the brief and label
// it federation, or encode/import a private Loro grant/envelope to get setup.
suite.todo(test, "FEDERATION-04", "waits on typed guest document share/envelope and foreign-world reshare calls");

// FEDERATION-05 — Cross-vault identity without pooled truth should work.
// OF-151; ARCH-0043#quarantine-and-coreference/#relationship-lifecycle.
// Fixture truth: host says Mira Chen lives in Helsinki; guest says the same
// named person lives in Lisbon. A separate host-only detail is never shared.
// Required typed identity-link contract: (local person, foreign-world person,
// proposed|confirmed status) -> atomic link/status receipt; owner consent
// names exactly one pact; unlink -> receipt retaining the original claims.
// Available recall: vault.recall({query,effort:"light",scope?:{world_ref},
// limit}) -> {items:[{short_id,world,provenance:{source,source_revision_ids,
// evidence_turn_ids},value_text,...}],narrowing,retrieval_meta,...}.
// Recall as each owner before/after link and after unlink. Assert each local
// claim retains its independently authored city and source, explicit foreign
// scope keeps the disagreeing claim foreign, and unscoped recall never pools
// them into one belief. Source labels/refs survive linking and unlinking.
// A guest read of the private detail stays refused before AND after linking;
// a same_as link is no read grant and its existence does not export consent.
// Missing: atomic typed cross-vault coreference link/owner-confirm/unlink and
// per-pact share-consent calls. A generic edge plus a status claim, merge/split,
// or vault.batch is not the owning typed operation G01 requires.
suite.todo(test, "FEDERATION-05", "waits on typed atomic cross-vault coreference link, consent and unlink calls");

// FEDERATION-06 — Disconnect stale content and courtesy deletion should work.
// OF-159/273; ARCH-0043#relationship-lifecycle; ARCH-0040#federation-admission.
// Receive the authorized guest copy publicly; observe its content and a public
// receipt/ACK before closing that client's socket. Keep its own vault intact.
// Disconnect at host while that client is offline. Normal recall excludes
// the retained foreign world; explicit recall scope.world_ref still returns
// the fixture sentence WITH stale_since/age/reason/pact-epoch metadata.
// Revoked future access and a recipient-owned retained copy are distinct.
// Send the courtesy request over its real authenticated public transport,
// reconnect, observe the request and choose deletion; inspect that no rows
// above epoch_cutoff were swept. Verify the client reports any discarded
// unsynced edits, without confusing that count with proof of remote erasure.
// Include a peer's refusal/retention outcome: it cannot restore access, and
// the host cannot claim the peer's already-received bytes were clawed back.
// Available vault.courtesy_delete.send({pact,worlds?,epoch_cutoff?,peer,signed?})
// -> {request,pact,recipient,status,created,updated}; incoming({}) ->
// [{request,pact,pact_status?,worlds:[{world,stale?,stale_epoch?}],epoch_cutoff,
// candidates,answer?,...}]; answer({pact,request,choice,delete?,hold?,...});
// sent({}) tracks queued/sent separately from the recipient's answer.
// Never fill signed with a helper-signed engine record. The hosts sign.
// Missing: typed disconnect and real foreign-world admission/rejoin path;
// the typed MemoryItem/MemoryProvenance recall result also has no stale stamp
// fields. Courtesy endpoints and additive internal stale rows do not expose
// this full public journey. Do not use restart as a pretend peer reconnect.
suite.todo(test, "FEDERATION-06", "waits on typed disconnect, foreign-world rejoin and stale-stamped recall result");

// FEDERATION-07 — Peer anomaly quarantines without losing review should work.
// OF-152/303; ARCH-0023b#decision-federation-26; ARCH-0040#mcp-actor-ceilings.
// G11=B IS RULED: assert configured routed outcome and receipt, never a
// universal model-score cutoff, absolute burst constant or human-pause rule.
// Required public policy/ingress contract: named peer baseline and vault-size
// context; authorized ordinary/anomalous batches -> a receipted discriminated
// allow | isolate-and-propose | defer result, with batch/review/replay refs.
// Exercise each configured policy outcome. If it consults a model, use the
// production adapter with independently scripted output. Feed real WS ingress,
// retaining ACK and receipt; never call Rust replay.
// Allow exposes exactly the authored ordinary rows. Isolate keeps anomalous
// rows out of normal recall and produces ONE retained review bundle. Owner
// release exposes only grant-authorized rows, preserves original provenance
// and cannot widen rejected authority. Defer persists the batch across rejoin
// and later public replay, without losing or duplicating its work. An ordinary
// second peer stays usable while the first has isolated/deferred work.
// Compare the same burst under distinct named baselines to make the relative
// policy observable. Assert bounded maintenance-band admission against its
// configured per-peer byte/window policy separately from the burst outcome;
// an old hard-quota error is not the canon's complete three-way response.
// Missing: typed relative-burst policy/baseline, disposition/review and durable
// deferred replay doors. No TODO waits on G11, and no score is invented here.
suite.todo(test, "FEDERATION-07", "waits on typed peer-relative burst policy, disposition/review and durable deferred replay");

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
