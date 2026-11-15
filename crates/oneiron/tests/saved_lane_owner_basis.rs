//! A saved lane never reads past the owner standing its live key held (FIX
//! 14344, Astra F2 on #8029; Engine RULING 15 Nov 07:42).
//!
//! The owner pairs their own device; its credential names the own-device
//! grant. The device hands the credential to a second key
//! (`CapabilitySlip::attenuate_to`): that key reads as a delegate, under the
//! relationship gate with no owner exemption, so it refuses the owner's
//! claim inside a relationship it holds no grant on. Saved work froze that
//! lane as its holder's principal lane, and its rebuild over the owner's own
//! key read the row: the saved question's asker key regained the owner's
//! exemption, its source key the owner alternative a missing Scope turns
//! on, and the owner's own key its floor. The lane now keeps its top Scope
//! and its live key's grant basis, and every rebuild reads no more than the
//! live lane did. An attenuated credential the device kept keeps its Scope
//! and its owner exemption, and the device's own credential still saves as
//! its holder's principal lane: both rebuilds still read the row.
//!
//! Red on #8029 (87747eae206): each transferred rebuild reads the
//! relationship claim, and both credentials' lanes read as their holder's
//! principal lane. Guard (green there too): the device's own saved question
//! and the attenuated one's read the relationship claim.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_lane_owner_basis`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{
    FrozenReadLane, ScopedRead, ScopedReadActorKey, base_world_id, default_project_id,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::ENTITY_TYPE_RELATIONSHIP;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::saved_question_reader::{asker_reader, question_read};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:saved-lane-owner-basis";
/// The binding key seed of the owner's paired device.
const DEVICE_BINDING_SEED: u8 = 0x4D;
/// The binding key seed of the key the device hands its credential to.
const DELEGATE_BINDING_SEED: u8 = 0x5E;
/// The caveat that narrows only the credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;

/// A vault whose owner wrote a base-world claim open to every relationship
/// and one inside a relationship no grant names, and paired their own
/// device.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    open_claim: EntityId,
    relationship_claim: EntityId,
    device_slip: CapabilitySlip,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"relationship",
        )
        .expect("a relationship");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let open_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        ClaimRelationships::All(AllRelationships::All),
    );
    let relationship_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        ClaimRelationships::Relationships(vec![relationship.to_hex()]),
    );
    let device_slip = paired_device_slip(&vault, &issuer, &owner_proof, owner);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        open_claim,
        relationship_claim,
        device_slip,
    }
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    relationships: ClaimRelationships,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!("saved lane owner basis claim"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: relationships,
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

/// The owner's own device pairs on a link the owner issues for themselves.
fn paired_device_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
) -> CapabilitySlip {
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
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the owner's device redeems the link")
}

/// `slip`, proved by the key whose seed is `seed`.
fn verified(fixture: &Fixture, slip: &CapabilitySlip, seed: u8) -> VerifiedSlip {
    let signature = SigningKey::from_bytes(&[seed; 32])
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the holder's request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            slip,
            REQUEST_CHALLENGE,
            &signature,
        )
        .expect("the holder proves possession of the credential")
}

fn lifetime_caveat() -> SlipCaveat {
    SlipCaveat {
        ttl_secs: Some(CAVEAT_TTL_SECS),
        ..Default::default()
    }
}

/// The device's credential handed to a second key, as that key proves it.
fn transferred_slip(fixture: &Fixture) -> VerifiedSlip {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate_to(
        lifetime_caveat(),
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
        SigningKey::from_bytes(&[DELEGATE_BINDING_SEED; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("the device hands its credential to a second key");
    let proof = verified(fixture, &slip, DELEGATE_BINDING_SEED);
    assert!(
        proof.is_transferred(),
        "precondition: the second key proves a transferred credential"
    );
    proof
}

/// The device's credential narrowed by the device itself, kept on its key.
fn attenuated_slip(fixture: &Fixture) -> VerifiedSlip {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        lifetime_caveat(),
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential");
    let proof = verified(fixture, &slip, DEVICE_BINDING_SEED);
    assert!(
        !proof.is_transferred() && !proof.is_full_vault_owner_grade(),
        "precondition: the device's attenuated credential stays on its key below the owner's floor"
    );
    proof
}

fn credential_key(fixture: &Fixture, proof: &VerifiedSlip) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(proof)
        .expect("the credential's read key")
        .expect("the credential grants read")
}

/// What `lane` reads of `claim` through two doors: the graph filesystem's
/// file and the point read. An error counts as a refusal; the text names
/// each door's answer.
fn reads(lane: &ScopedRead<'_>, claim: EntityId) -> (bool, String) {
    let file = lane
        .graph_fs(GraphFsOptions::default())
        .read_file(&format!("/worlds/base/claims/{}", claim.to_hex()))
        .map(|read| read.value.is_some());
    let point = lane
        .get_entity_parts_with_receipt(&claim, None)
        .map(|read| read.value.is_some());
    let read = matches!(file, Ok(true)) || matches!(point, Ok(true));
    (read, format!("graph_fs={file:?} point={point:?}"))
}

fn held_lane(fixture: &Fixture, key: ScopedReadActorKey) -> ScopedRead<'_> {
    fixture
        .vault
        .scoped_read(key)
        .recorded_lane()
        .expect("record read lane")
}

/// A saved question's lane under `key`, with its reader's own live owner
/// authority, reading recorded claims as `held_lane` does.
fn question_lane(fixture: &Fixture, key: ScopedReadActorKey) -> ScopedRead<'_> {
    question_read(&fixture.vault, key)
        .recorded_lane()
        .expect("record question lane")
}

/// `key`'s lane frozen as saved work keeps it, read back from its stored
/// MessagePack form, as a saved question's and a queued summary's lane is.
fn saved_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(key)
        .freeze()
        .expect("the credential's read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// What a saved question's asker reader reads of `claim`: the owner's own
/// asker key narrowed by `frozen`, with the owner's own live authority.
fn asker_reads(fixture: &Fixture, frozen: &FrozenReadLane, claim: EntityId) -> (bool, String) {
    match asker_reader(&fixture.vault, fixture.owner, frozen) {
        Ok(key) => reads(&question_lane(fixture, key), claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// What a saved question's source reader (its refresh, artifact and wake
/// reads) reads of `claim`: the owner's bare key under the access gate,
/// narrowed by `frozen`, with the owner's own live authority.
fn source_reads(fixture: &Fixture, frozen: &FrozenReadLane, claim: EntityId) -> (bool, String) {
    let key = ScopedReadActorKey::with_actor_class(fixture.owner.to_hex(), "human")
        .expect("owner principal key")
        .require_access_grants(Some(fixture.owner));
    match frozen.narrow(&fixture.vault, key) {
        Ok(key) => reads(&question_lane(fixture, key), claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// What `frozen`, rebuilt over the owner's own in-process key, reads of
/// `claim`.
fn owner_key_reads(fixture: &Fixture, frozen: &FrozenReadLane, claim: EntityId) -> (bool, String) {
    let key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    match frozen.narrow(&fixture.vault, key) {
        Ok(key) => reads(&held_lane(fixture, key), claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// The transferred credential's live lane reads the open claim and refuses
/// the relationship one, which the owner's own key reads: the row each
/// rebuild must not read.
fn transferred_saved_lane(fixture: &Fixture) -> FrozenReadLane {
    let key = credential_key(fixture, &transferred_slip(fixture));
    let lane = held_lane(fixture, key.clone());
    let (open, seen) = reads(&lane, fixture.open_claim);
    assert!(
        open,
        "precondition: the transferred credential's live lane reads the owner's open claim; seen {seen}"
    );
    let (refused, seen) = reads(&lane, fixture.relationship_claim);
    assert!(
        !refused,
        "precondition: the transferred credential's live lane refuses the owner's claim in a relationship it holds no grant on; seen {seen}"
    );
    let owner = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    let (owner, seen) = reads(&held_lane(fixture, owner), fixture.relationship_claim);
    assert!(
        owner,
        "control: the owner's own key reads the relationship claim; seen {seen}"
    );
    saved_lane(fixture, key)
}

#[test]
fn a_transferred_own_device_lane_freezes_with_its_scope() {
    let fixture = fixture();
    let frozen = transferred_saved_lane(&fixture);
    assert!(
        !frozen.reads_as_principal(),
        "actor=a key the owner's device handed its credential to; expected its saved lane to keep its Scope, not to read as its holder's principal lane"
    );
}

#[test]
fn a_transferred_own_device_saved_question_asker_reads_no_row_its_live_lane_refused() {
    let fixture = fixture();
    let frozen = transferred_saved_lane(&fixture);
    let (open, seen) = asker_reads(&fixture, &frozen, fixture.open_claim);
    assert!(
        open,
        "actor=a key the owner's device handed its credential to; expected its saved question's asker reader to read the open claim its live lane read; seen {seen}"
    );
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.relationship_claim);
    assert!(
        !read,
        "actor=a key the owner's device handed its credential to; expected its saved question's asker reader to refuse the relationship claim its live lane refused; seen {seen}"
    );
}

#[test]
fn a_transferred_own_device_saved_question_source_reads_no_row_its_live_lane_refused() {
    let fixture = fixture();
    let frozen = transferred_saved_lane(&fixture);
    let (read, seen) = source_reads(&fixture, &frozen, fixture.relationship_claim);
    assert!(
        !read,
        "actor=a key the owner's device handed its credential to; expected its saved question's source reader to refuse the relationship claim its live lane refused; seen {seen}"
    );
}

#[test]
fn a_transferred_own_device_saved_lane_over_the_owners_key_reads_no_row_its_live_lane_refused() {
    let fixture = fixture();
    let frozen = transferred_saved_lane(&fixture);
    let (read, seen) = owner_key_reads(&fixture, &frozen, fixture.relationship_claim);
    assert!(
        !read,
        "actor=a key the owner's device handed its credential to; expected its saved lane, rebuilt over the owner's own key, to refuse the relationship claim its live lane refused; seen {seen}"
    );
}

/// The attenuated credential kept the owner's exemption: its live lane and
/// its saved question read the relationship claim; only its saved shape
/// changes.
#[test]
fn an_attenuated_own_device_lane_freezes_with_its_scope_and_its_owner_exemption() {
    let fixture = fixture();
    let key = credential_key(&fixture, &attenuated_slip(&fixture));
    let (live, seen) = reads(
        &held_lane(&fixture, key.clone()),
        fixture.relationship_claim,
    );
    assert!(
        live,
        "precondition: the device's attenuated credential reads the owner's relationship claim under the owner's exemption; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.relationship_claim);
    assert!(
        read,
        "actor=the owner's device under an attenuated credential; expected its saved question's asker reader to keep the owner's exemption and read the relationship claim; seen {seen}"
    );
    assert!(
        !frozen.reads_as_principal(),
        "actor=the owner's device under an attenuated credential; expected its saved lane to keep its Scope, not to read as its holder's principal lane"
    );
}

/// Guard: the device's own credential reads as the owner, and its saved
/// question still reads as the owner's own.
#[test]
fn an_own_device_saved_question_reads_the_owners_relationship_row() {
    let fixture = fixture();
    let key = credential_key(
        &fixture,
        &verified(&fixture, &fixture.device_slip, DEVICE_BINDING_SEED),
    );
    let frozen = saved_lane(&fixture, key);
    assert!(
        frozen.reads_as_principal(),
        "actor=the owner's paired device; expected its saved lane to read as its holder's principal lane"
    );
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.relationship_claim);
    assert!(
        read,
        "actor=the owner's paired device; expected its saved question's asker reader to read the owner's relationship claim; seen {seen}"
    );
}
