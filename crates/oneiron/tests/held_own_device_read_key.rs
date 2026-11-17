//! A read key held past its verification reads only while the own-device
//! grant its slip names stands (FIX OWN-DEVICE-GRANT-NOT-RECHECKED, Engine
//! TASK 15 Nov 06:02): "The grant is checked live at each use and is
//! revocable" (Substrate behind grants, canon oneiron/system.md:40).
//!
//! The owner pairs their own device, and its credential's read key is built
//! once. Deleting the own-device grant appends no slip revoke, so the
//! authority fold alone still calls the slip live: only a fresh verification
//! judged the grant, and a key held past it read on. Each read under the key
//! now judges the grant in its own snapshot (`ScopedRead::proof_live_in`).
//!
//! Saved work (a saved question's or a queued summary's lane, OF-506) froze
//! the device's unrestricted lane as its holder's principal lane, which
//! keeps no credential: its rebuild over the owner's own key read on after
//! the delete. The frozen lane now keeps the credential's id, each rebuild
//! judges its grant (FrozenReadLane::freeze), and the rebuilt key carries
//! the credential, so a key rebuilt before the delete and held past it, or
//! frozen again, reads nothing after it.
//!
//! Red on main: a held lane, a key rebuilt from the same verified slip, a
//! saved lane rebuilt after the delete, a saved lane's key rebuilt before
//! the delete and a lane frozen again from that key all still read the
//! owner's claim. Guard (green on main too): a held lane whose grant stands
//! reads on after another grant's delete, and each saved lane rebuilt
//! before the delete reads.
//! The owner's own key reads the claim throughout, so a refused read is the
//! credential's, not a missing row.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test held_own_device_read_key`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{
    FrozenReadLane, ScopedRead, ScopedReadActorKey, base_world_id, default_project_id,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::house_link::is_own_device_grant;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:held-own-device-read-key";
/// The binding key seed of the owner's paired device.
const DEVICE_BINDING_SEED: u8 = 0x4D;

/// A vault whose owner wrote one claim and paired their own device: the
/// device's verified slip and the own-device grant it names.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    claim: EntityId,
    claim_path: String,
    device_slip: VerifiedSlip,
    device_grant: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link and agent Grant are owner acts this install's
    // live machine profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let claim = write_owner_claim(&vault, owner, &owner_proof);
    let device_slip = paired_device_slip(&vault, &issuer, &owner_proof, owner);
    let device_grant = device_slip
        .claims()
        .grant_ref
        .as_deref()
        .map(EntityId::from_hex)
        .expect("the owner's paired slip names their own-device grant (FIX 3134)")
        .expect("the named grant is an entity id");
    assert!(
        is_own_device_grant(&vault, device_grant).expect("the grant row reads"),
        "precondition: the grant the device's slip names is an own-device grant: {device_grant:?}"
    );
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
        claim,
        claim_path: format!("/worlds/base/claims/{}", claim.to_hex()),
        device_slip,
        device_grant,
    }
}

fn write_owner_claim(vault: &Vault, owner: EntityId, owner_proof: &AuthenticatedOwner) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!("held own-device key claim"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a base-world claim");
    id
}

/// The owner's own device pairs on a link the owner issues for themselves,
/// and proves possession of the slip it redeems.
fn paired_device_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
) -> VerifiedSlip {
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link for their own device");
    let signing_key = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the device's pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the owner's device redeems the link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the device's request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("the paired device proves possession of its credential")
}

/// What `lane` reads of the fixture's claim through two doors: the graph
/// filesystem's file and the point read. `None` is a read that refused
/// (an error counts as a refusal); the text names each door's answer.
fn claim_reads(fixture: &Fixture, lane: &ScopedRead<'_>) -> (bool, String) {
    let file = lane
        .graph_fs(GraphFsOptions::default())
        .read_file(&fixture.claim_path)
        .map(|read| read.value.is_some());
    let point = lane
        .get_entity_parts_with_receipt(&fixture.claim, None)
        .map(|read| read.value.is_some());
    let reads = matches!(file, Ok(true)) || matches!(point, Ok(true));
    (reads, format!("graph_fs={file:?} point={point:?}"))
}

/// A held read lane under `key`, as a request or session keeps it.
fn held_lane(fixture: &Fixture, key: ScopedReadActorKey) -> ScopedRead<'_> {
    fixture
        .vault
        .scoped_read(key)
        .recorded_lane()
        .expect("record read lane")
}

/// A read key for the device's slip, built now.
fn device_key(fixture: &Fixture) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(&fixture.device_slip)
        .expect("the device's credential read key")
        .expect("the device's credential grants read")
}

/// The owner's own in-process key, which no slip backs.
fn owner_key(fixture: &Fixture) -> ScopedReadActorKey {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key")
}

/// What the owner's own key reads of the fixture's claim.
fn owner_reads(fixture: &Fixture) -> (bool, String) {
    claim_reads(fixture, &held_lane(fixture, owner_key(fixture)))
}

/// The device's read lane frozen as saved work keeps it, and read back
/// from its stored MessagePack form, as a saved question's and a queued
/// summary's lane is.
fn saved_device_lane(fixture: &Fixture) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(device_key(fixture))
        .freeze()
        .expect("the paired device's read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// What `frozen`, rebuilt now over the owner's own key as saved work's
/// reader is, reads of the fixture's claim. A rebuild that errs reads
/// nothing.
fn saved_lane_reads(fixture: &Fixture, frozen: &FrozenReadLane) -> (bool, String) {
    match frozen.narrow(&fixture.vault, owner_key(fixture)) {
        Ok(key) => claim_reads(fixture, &held_lane(fixture, key)),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// The grant row deleted through the vault's public delete: a plain delete
/// appends no authority act and no slip revoke.
fn delete_grant(fixture: &Fixture, grant: EntityId) {
    assert!(
        fixture
            .vault
            .delete_entity(&grant)
            .expect("public Grant deletion"),
        "the live grant {grant:?} was deleted"
    );
}

fn device_slip_is_live(fixture: &Fixture) -> bool {
    fixture
        .vault
        .capability_slip_is_live(&fixture.device_slip)
        .expect("judge the device's slip")
}

#[test]
fn a_held_read_lane_reads_nothing_once_its_own_device_grant_is_deleted() {
    let fixture = fixture();
    let lane = held_lane(&fixture, device_key(&fixture));
    let (before, seen) = claim_reads(&fixture, &lane);
    assert!(
        before,
        "actor=owner's paired device; expected its held lane to read the owner's claim while its own-device grant stands; seen {seen}"
    );

    delete_grant(&fixture, fixture.device_grant);
    assert!(
        !device_slip_is_live(&fixture),
        "precondition: a fresh judgment refuses the device's slip once its own-device grant is deleted"
    );
    let (after, seen) = claim_reads(&fixture, &lane);
    assert!(
        !after,
        "actor=owner's paired device; expected its held lane to read nothing once its own-device grant {:?} is deleted; seen {seen}",
        fixture.device_grant
    );
    let (owner, seen) = owner_reads(&fixture);
    assert!(
        owner,
        "control: the owner's own key still reads the claim; seen {seen}"
    );
}

#[test]
fn a_read_key_rebuilt_after_its_own_device_grant_is_deleted_reads_nothing() {
    let fixture = fixture();
    delete_grant(&fixture, fixture.device_grant);
    assert!(
        !device_slip_is_live(&fixture),
        "precondition: a fresh judgment refuses the device's slip once its own-device grant is deleted"
    );
    // The builder may still answer a key for the owner's held verified slip
    // (its owner fallback); what binds is that the key reads nothing.
    match fixture.vault.credential_read_key(&fixture.device_slip) {
        Ok(Some(key)) => {
            let (reads, seen) = claim_reads(&fixture, &held_lane(&fixture, key));
            assert!(
                !reads,
                "actor=owner's paired device; expected a key rebuilt after its own-device grant {:?} is deleted to read nothing; seen {seen}",
                fixture.device_grant
            );
        }
        Ok(None) | Err(_) => {}
    }
    let (owner, seen) = owner_reads(&fixture);
    assert!(
        owner,
        "control: the owner's own key still reads the claim; seen {seen}"
    );
}

/// Sol threat read F1 (15 Nov 06:31): the lane rides its stored MessagePack
/// form, as a saved question's and a queued summary's do.
#[test]
fn a_saved_lane_rebuilt_after_its_own_device_grant_is_deleted_reads_nothing() {
    let fixture = fixture();
    let frozen = saved_device_lane(&fixture);
    let (before, seen) = saved_lane_reads(&fixture, &frozen);
    assert!(
        before,
        "actor=owner's paired device; expected its saved lane, rebuilt while its own-device grant stands, to read the owner's claim; seen {seen}"
    );

    delete_grant(&fixture, fixture.device_grant);
    let (after, seen) = saved_lane_reads(&fixture, &frozen);
    assert!(
        !after,
        "actor=owner's paired device; expected its saved lane, rebuilt after its own-device grant {:?} is deleted, to read nothing; seen {seen}",
        fixture.device_grant
    );
    let (owner, seen) = owner_reads(&fixture);
    assert!(
        owner,
        "control: the owner's own key still reads the claim; seen {seen}"
    );
}

/// Sol review R1 of #8029 (15 Nov 06:55): saved work holds the key it
/// rebuilt across its own later snapshots (a saved question's reader, a
/// summary's reply lane), so the key itself must judge the grant at each
/// read, not only its rebuild.
#[test]
fn a_saved_lane_key_rebuilt_before_its_own_device_grant_is_deleted_reads_nothing_after_it() {
    let fixture = fixture();
    let frozen = saved_device_lane(&fixture);
    let rebuilt = held_lane(
        &fixture,
        frozen
            .narrow(&fixture.vault, owner_key(&fixture))
            .expect("the saved lane rebuilds while its own-device grant stands"),
    );
    let (before, seen) = claim_reads(&fixture, &rebuilt);
    assert!(
        before,
        "actor=owner's paired device; expected its saved lane's key, rebuilt while its own-device grant stands, to read the owner's claim; seen {seen}"
    );

    delete_grant(&fixture, fixture.device_grant);
    let (after, seen) = claim_reads(&fixture, &rebuilt);
    assert!(
        !after,
        "actor=owner's paired device; expected its saved lane's key, rebuilt before its own-device grant {:?} was deleted, to read nothing after the delete; seen {seen}",
        fixture.device_grant
    );
    let (owner, seen) = owner_reads(&fixture);
    assert!(
        owner,
        "control: the owner's own key still reads the claim; seen {seen}"
    );
}

/// Sol review R1 of #8029 (15 Nov 06:55): a rebuilt key holds no proof, so
/// freezing it again kept no credential and became the owner's principal
/// lane; the key now carries the credential, and the second freeze keeps it.
#[test]
fn a_saved_lane_frozen_again_from_its_rebuilt_key_reads_nothing_once_its_own_device_grant_is_deleted()
 {
    let fixture = fixture();
    let rebuilt = saved_device_lane(&fixture)
        .narrow(&fixture.vault, owner_key(&fixture))
        .expect("the saved lane rebuilds while its own-device grant stands");
    let refrozen = fixture
        .vault
        .scoped_read(rebuilt)
        .freeze()
        .expect("the rebuilt lane freezes again");
    let (before, seen) = saved_lane_reads(&fixture, &refrozen);
    assert!(
        before,
        "actor=owner's paired device; expected its lane frozen again from the rebuilt key to read the owner's claim while its own-device grant stands; seen {seen}"
    );

    delete_grant(&fixture, fixture.device_grant);
    let (after, seen) = saved_lane_reads(&fixture, &refrozen);
    assert!(
        !after,
        "actor=owner's paired device; expected its lane frozen again from the rebuilt key, rebuilt after its own-device grant {:?} is deleted, to read nothing; seen {seen}",
        fixture.device_grant
    );
    let (owner, seen) = owner_reads(&fixture);
    assert!(
        owner,
        "control: the owner's own key still reads the claim; seen {seen}"
    );
    assert!(
        !refrozen.is_principal(),
        "actor=owner's paired device; expected the lane frozen again from the rebuilt key to keep the device's credential, not become the owner's principal lane"
    );
}

#[test]
fn a_held_read_lane_reads_on_while_its_own_device_grant_stands() {
    let fixture = fixture();
    let lane = held_lane(&fixture, device_key(&fixture));
    let (before, seen) = claim_reads(&fixture, &lane);
    assert!(
        before,
        "actor=owner's paired device; expected its held lane to read the owner's claim; seen {seen}"
    );

    // Another grant of the vault is minted and deleted: the per-use check
    // judges the slip's own grant, not every grant's withdrawal.
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "held_own_device_read_key_agent",
                "desc": "Held own-device read key control",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let agent_grant = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a read Grant")
    .grant
    .grant_ref;
    assert_ne!(
        agent_grant, fixture.device_grant,
        "precondition: the agent's Grant is not the device's own-device grant"
    );
    delete_grant(&fixture, agent_grant);

    assert!(
        device_slip_is_live(&fixture),
        "precondition: the device's slip stands while its own-device grant does"
    );
    let (held, seen) = claim_reads(&fixture, &lane);
    assert!(
        held,
        "actor=owner's paired device; expected its held lane to read on while its own-device grant stands; seen {seen}"
    );
    let (rebuilt, seen) = claim_reads(&fixture, &held_lane(&fixture, device_key(&fixture)));
    assert!(
        rebuilt,
        "actor=owner's paired device; expected a key built now to read while its own-device grant stands; seen {seen}"
    );
}
