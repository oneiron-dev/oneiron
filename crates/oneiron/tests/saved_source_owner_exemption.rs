//! A saved question's source reader keeps the owner's exemption its asker
//! reader holds (FIX SAVED-SOURCE-DROPS-OWNER-EXEMPTION, Sol F2 on #8061;
//! OPUS-SECREAD-A N2 and the Sol review of #8109).
//!
//! The owner's own key, and a narrower credential of the owner's, read a
//! relationship's rows past the grant gate while the owner is still the
//! vault's bound owner (`exempt_while_owner`). A saved question's asker
//! reader rebuilds the principal's key with that exemption. Its source
//! reader, which the question's refresh, artifact asks and withdrawal wakes
//! read through (`saved_source_key_in_txn`), rebuilt the principal's bare
//! key under the access gate with no exemption, so the saved lane met with
//! it dropped the exemption the lane's live key held: the source reads
//! refused the owner's MESSAGE in a relationship the owner holds no grant
//! in, and the owner's MESSAGE that names no relationship, which the live
//! lane and the asker reader read. The owner's own lane read the same way:
//! its owner authority copies the access gate. The source reader now
//! builds the principal's key with the exemption while the principal is the
//! vault's live owner, proved again at each read; the saved lane keeps it
//! only where its live key held an owner standing.
//!
//! Red at 382d40476b6 (#8134's head): the owner's attenuated device lane
//! and the owner's own lane source-read neither MESSAGE. Guards: the asker
//! reader of the device lane reads both; the owner's agent-class credential,
//! whose live key held no owner standing, gains none (its source reader
//! still refuses the relationship MESSAGE); the house, which is no owner,
//! still source-reads the owner's unscoped MESSAGE under the access gate,
//! which refuses it.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_source_owner_exemption`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::question_saved_lane::{
    question_read, saved_question_reader, saved_source_reader, under_relationship_gate,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:saved-source-owner-exemption";
/// The binding key seed of the owner's agent-class credential.
const AGENT_BINDING_SEED: u8 = 0x7A;
/// The binding key seed of the owner's own human-class device.
const DEVICE_BINDING_SEED: u8 = 0x7B;
/// The caveat that narrows only the device credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;

/// A vault whose owner witnessed two MESSAGEs, one in a relationship the
/// owner holds no grant in and one that names no relationship, and paired
/// an agent-class credential and a human-class device on their own PERSON;
/// and the house mind the vault seeds.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    house: EntityId,
    relationship_message: EntityId,
    unscoped_message: EntityId,
    agent_slip: CapabilitySlip,
    device_slip: CapabilitySlip,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let house = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded agent definition read")
        .expect("the fresh vault seeds sys.team_lead")
        .0;
    let relationship_message = EntityId::now();
    let unscoped_message = EntityId::now();
    let message = |id: EntityId, order: u32, words: &str, metadata| WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "text".to_owned(),
        content: words.to_owned(),
        parts: None,
        metadata: Some(metadata),
        is_visible: true,
        order,
        quote: None,
    };
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            occurred_at: 1,
            messages: vec![
                // A relationship no PERSON is a member of and no grant names.
                message(
                    relationship_message,
                    0,
                    "The allotment committee meets on Thursday.",
                    json!({ "rel": EntityId::now().to_hex() }),
                ),
                message(
                    unscoped_message,
                    1,
                    "The spring garden needs a watering rota.",
                    json!({}),
                ),
            ],
            assertions: Default::default(),
        })
        .expect("the owner's turn lands");
    let agent_slip = paired_slip(
        &vault,
        &issuer,
        &owner_proof,
        owner,
        "agent",
        AGENT_BINDING_SEED,
    );
    let device_slip = paired_slip(
        &vault,
        &issuer,
        &owner_proof,
        owner,
        "human",
        DEVICE_BINDING_SEED,
    );
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        house,
        relationship_message,
        unscoped_message,
        agent_slip,
        device_slip,
    }
}

/// A credential on the owner's own PERSON, naming `class`, paired on a link
/// the owner issues and redeemed by the key whose seed is `seed`.
fn paired_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
    class: &str,
    seed: u8,
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
                actor_class: Some(class.to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link on their own PERSON");
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the pairing transcript");
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the credential's key redeems the link")
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

fn credential_key(fixture: &Fixture, proof: &VerifiedSlip) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(proof)
        .expect("the credential's read key")
        .expect("the credential grants read")
}

/// The owner's device credential narrowed by the device itself, kept on its
/// key: a human-class key below the owner's floor, holding the owner's
/// exemption (`credential_read_key`).
fn attenuated_device_key(fixture: &Fixture) -> ScopedReadActorKey {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            ..Default::default()
        },
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential");
    let key = credential_key(fixture, &verified(fixture, &slip, DEVICE_BINDING_SEED));
    assert!(
        key.actor_class() == Some("human") && !key.reads_as_vault_owner(),
        "precondition: the device's attenuated credential reads as a human, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// The owner's agent-class credential's live key: no owner standing.
fn agent_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = credential_key(
        fixture,
        &verified(fixture, &fixture.agent_slip, AGENT_BINDING_SEED),
    );
    assert!(
        key.actor_class() == Some("agent") && !key.reads_as_vault_owner(),
        "precondition: the owner's agent-class credential reads as an agent, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// `key`'s lane frozen as saved work keeps it, read back from its stored
/// MessagePack form, as a saved question's lane is.
fn saved_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(key)
        .freeze()
        .expect("the read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// The device credential's saved lane, once its live lane is shown to read
/// both MESSAGEs.
fn device_saved_lane(fixture: &Fixture) -> FrozenReadLane {
    let key = attenuated_device_key(fixture);
    let live = fixture.vault.scoped_read(key.clone());
    for (row, name) in [
        (fixture.relationship_message, "relationship"),
        (fixture.unscoped_message, "unscoped"),
    ] {
        let (read, seen) = reads(&live, row);
        assert!(
            read,
            "precondition: the device's attenuated credential, under the owner's exemption, reads the owner's {name} MESSAGE; seen {seen}"
        );
    }
    let frozen = saved_lane(fixture, key);
    assert!(
        !frozen.reads_as_principal(),
        "precondition: the device's attenuated credential's saved lane keeps its Scope and basis, not its holder's principal lane"
    );
    frozen
}

/// What `principal`'s saved question source-reads of `row` (its refresh,
/// artifact and wake reads), saved under `frozen`.
fn source_reads(
    fixture: &Fixture,
    principal: EntityId,
    frozen: &FrozenReadLane,
    row: EntityId,
) -> (bool, String) {
    match saved_source_reader(&fixture.vault, principal, frozen) {
        Ok(key) => reads(&question_read(&fixture.vault, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// What the owner's saved question reads of `row` through its asker
/// reader, saved under `frozen`.
fn asker_reads(fixture: &Fixture, frozen: &FrozenReadLane, row: EntityId) -> (bool, String) {
    match saved_question_reader(&fixture.vault, fixture.owner, frozen) {
        Ok(key) => reads(&question_read(&fixture.vault, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

#[test]
fn an_owner_device_saved_lane_source_reads_the_relationship_message_its_live_lane_read() {
    let fixture = fixture();
    let frozen = device_saved_lane(&fixture);
    let (read, seen) = source_reads(
        &fixture,
        fixture.owner,
        &frozen,
        fixture.relationship_message,
    );
    assert!(
        read,
        "actor=the owner's device under an attenuated credential; expected its saved question's source reader to keep the owner's exemption and read the MESSAGE in a relationship the owner holds no grant in; seen {seen}"
    );
}

#[test]
fn an_owner_device_saved_lane_source_reads_the_unscoped_message_its_live_lane_read() {
    let fixture = fixture();
    let frozen = device_saved_lane(&fixture);
    let (read, seen) = source_reads(&fixture, fixture.owner, &frozen, fixture.unscoped_message);
    assert!(
        read,
        "actor=the owner's device under an attenuated credential; expected its saved question's source reader to read the owner's MESSAGE that names no relationship; seen {seen}"
    );
}

#[test]
fn the_owners_own_lane_source_reads_its_relationship_and_unscoped_messages() {
    let fixture = fixture();
    for (row, name) in [
        (fixture.relationship_message, "relationship"),
        (fixture.unscoped_message, "unscoped"),
    ] {
        let (read, seen) = source_reads(&fixture, fixture.owner, &FrozenReadLane::principal(), row);
        assert!(
            read,
            "actor=the owner, own lane; expected the owner's saved question's source reader to read the owner's {name} MESSAGE; seen {seen}"
        );
    }
}

/// Guard: the asker reader of the same lane already kept the exemption.
#[test]
fn an_owner_device_saved_lane_asker_reader_still_reads_both_messages() {
    let fixture = fixture();
    let frozen = device_saved_lane(&fixture);
    for (row, name) in [
        (fixture.relationship_message, "relationship"),
        (fixture.unscoped_message, "unscoped"),
    ] {
        let (read, seen) = asker_reads(&fixture, &frozen, row);
        assert!(
            read,
            "actor=the owner's device under an attenuated credential; expected its saved question's asker reader to read the owner's {name} MESSAGE; seen {seen}"
        );
    }
}

/// Guard: a lane whose live key held no owner standing gains none from the
/// source reader's exemption.
#[test]
fn an_owner_agent_class_saved_lane_source_reads_no_relationship_message() {
    let fixture = fixture();
    let key = agent_key(&fixture);
    let (live, seen) = reads(
        &fixture.vault.scoped_read(key.clone()),
        fixture.relationship_message,
    );
    assert!(
        !live,
        "precondition: the owner's agent-class credential, with no owner standing, refuses the MESSAGE in a relationship no grant names; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = source_reads(
        &fixture,
        fixture.owner,
        &frozen,
        fixture.relationship_message,
    );
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved question's source reader to gain no owner exemption and refuse the relationship MESSAGE; seen {seen}"
    );
}

/// Guard: a principal that is no owner keeps the access gate on its own
/// grants, which refuses a MESSAGE that names no relationship.
#[test]
fn the_house_own_lane_source_reads_no_unscoped_owner_message() {
    let fixture = fixture();
    let relationship_gated = under_relationship_gate(
        ScopedReadActorKey::with_actor_class(fixture.house.to_hex(), "agent")
            .expect("the house's bare agent key"),
        fixture.house,
    );
    let (live, seen) = reads(
        &fixture.vault.scoped_read(relationship_gated),
        fixture.unscoped_message,
    );
    assert!(
        live,
        "precondition: the house's key under the relationship gate reads the owner's unscoped MESSAGE under its policy row; seen {seen}"
    );
    let (read, seen) = source_reads(
        &fixture,
        fixture.house,
        &FrozenReadLane::principal(),
        fixture.unscoped_message,
    );
    assert!(
        !read,
        "actor=the house, own lane; expected its saved question's source reader to stay under the access gate and refuse the owner's unscoped MESSAGE; seen {seen}"
    );
}
