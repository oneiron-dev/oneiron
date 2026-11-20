//! A read under a narrower owner credential limited to some facets judges the
//! owner's exemption from those facets once per read, not once per row it
//! reads (FIX FACET-GATE-OWNER-EXEMPTION-PER-ROW).
//!
//! The owner's narrower credential reads past every facet while its holder
//! is still the vault's bound owner, proved again in the read's own snapshot
//! (`owner_exemption_holds_in_txn`, owner ruling FACET-READ = A). That proof
//! tests the owner's PERSON for liveness, which folds the identity
//! lifecycle. The facet gate (`claim/scoped_read/facet_gate.rs`) ran it for
//! every row it judged, whenever the credential named fewer than all facets.
//! The read's held authority already holds the verdict for the relationship
//! gate (FIX OWNER-EXEMPTION-LIFECYCLE-FOLD-PER-ROW); the facet gate now takes
//! it from there too.
//!
//! The owner's device credential, narrowed by the device itself to one FACET
//! that no row sits in, holds the owner's exemption below the owner's floor
//! (as in `tests/owner_exemption_judged_once_per_read.rs`). It reads the
//! edges out of a TURN whose MESSAGEs each sit in a relationship no PERSON is
//! a member of and no grant names: the TURN is retrieved only when every
//! MESSAGE in it reads, so each MESSAGE meets the facet gate under that
//! exemption. A test door counts the exemption judgements
//! (`test_doors::owner_exemption_judgements`); a TURN of eight MESSAGEs must
//! cost no more of them than a TURN of two.
//!
//! Expected red on main 0aedc807c52, by reading (not run before READY): the
//! eight-MESSAGE read judges the exemption at least six more times than the
//! two-MESSAGE read, once more per MESSAGE at the facet gate. Guard:
//! `each_read_under_a_facet_limited_owner_credential_judges_its_exemption_again`,
//! the verdict never outlives its read.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test facet_gate_owner_exemption_once_per_read`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{ScopedRead, ScopedReadActorKey};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_exemption_judgements::count_owner_exemption_judgements;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:facet-gate-owner-exemption-once-per-read";
/// The binding key seed of the owner's own human-class device.
const DEVICE_BINDING_SEED: u8 = 0x7E;
/// The MESSAGEs of the small TURN.
const FEW: usize = 2;
/// The MESSAGEs of the large TURN.
const MANY: usize = 8;

/// A vault whose owner paired a human-class device on their own PERSON,
/// holds one FACET no row sits in, and witnessed two TURNs, of `FEW` and
/// `MANY` MESSAGEs, each MESSAGE in its own relationship that no PERSON is a
/// member of and no grant names.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    device_slip: CapabilitySlip,
    facet: EntityId,
    few_turn: EntityId,
    many_turn: EntityId,
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
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            &issuer,
            &owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("human".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link on their own PERSON");
    let signing_key = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the pairing transcript");
    let device_slip = vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the device's key redeems the link");
    let facet = EntityId::now();
    vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({ "name": "allotment" })).expect("a facet body"),
        )
        .expect("the FACET row lands");
    let few_turn = witness_relationship_turn(&vault, owner, FEW);
    let many_turn = witness_relationship_turn(&vault, owner, MANY);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        device_slip,
        facet,
        few_turn,
        many_turn,
    }
}

/// `author`'s TURN of `messages` MESSAGEs, witnessed as the human it is,
/// each in its own relationship no PERSON is a member of and no grant names.
fn witness_relationship_turn(vault: &Vault, author: EntityId, messages: usize) -> EntityId {
    let messages = (0..messages)
        .map(|order| WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".to_owned(),
            content: format!("The allotment rota note number {order}."),
            parts: None,
            metadata: Some(json!({ "rel": EntityId::now().to_hex() })),
            is_visible: true,
            order: u32::try_from(order).expect("a small order"),
            quote: None,
        })
        .collect();
    vault
        .memory(author, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 1,
            messages,
            assertions: Default::default(),
        })
        .expect("the author's turn lands")
        .turn_id
}

/// The device credential narrowed by the device itself to the fixture's one
/// FACET, proved by its key and kept on its read key: a human-class key
/// below the owner's floor, limited to fewer than all facets and holding the
/// owner's exemption from them (`credential_read_key`).
fn facet_limited_device_key(fixture: &Fixture) -> ScopedReadActorKey {
    let mut scope = Scope::top();
    scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.facet)]));
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        },
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential to one facet");
    let proof = verified(fixture, &slip);
    assert!(
        proof.scope().facets == ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.facet)])),
        "precondition: the proved credential names one facet, fewer than all; seen {:?}",
        proof.scope().facets
    );
    assert!(
        fixture
            .vault
            .credential_facets_owner_exempt(&proof)
            .expect("the owner exemption reads"),
        "precondition: the owner's narrowed device credential is exempt from its facets while the owner {:?} is still bound",
        fixture.owner
    );
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("the credential's read key")
        .expect("the credential grants read");
    assert!(
        key.actor_class() == Some("human") && !key.reads_as_vault_owner(),
        "precondition: the device's narrowed credential reads as a human, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// `slip`, proved by the device's key.
fn verified(fixture: &Fixture, slip: &CapabilitySlip) -> VerifiedSlip {
    let signature = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32])
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

/// The owner exemption judgements one read of the edges out of `turn`
/// makes under `lane`, once the read is shown to retrieve the TURN, and so
/// to read every MESSAGE in it though none sits in the credential's facet.
fn judgements_of_one_read(lane: &ScopedRead<'_>, turn: EntityId, name: &str) -> usize {
    let (read, judgements) = count_owner_exemption_judgements(|| lane.edges_out(&turn));
    let read = read.map(|read| read.value.map(|edges| edges.len()));
    assert!(
        matches!(read, Ok(Some(_))),
        "precondition: the owner's facet-limited device credential retrieves the {name} TURN, no MESSAGE of which sits in its facet; seen {read:?}"
    );
    judgements
}

#[test]
fn a_facet_limited_owner_credential_judges_its_exemption_once_per_read_however_many_rows_it_reads()
{
    let fixture = fixture();
    let lane = fixture
        .vault
        .scoped_read(facet_limited_device_key(&fixture));
    let few = judgements_of_one_read(&lane, fixture.few_turn, "two-MESSAGE");
    let many = judgements_of_one_read(&lane, fixture.many_turn, "eight-MESSAGE");
    assert!(
        few >= 1,
        "precondition: a read under the owner's facet-limited credential proves the owner's exemption in its own snapshot; seen {few} judgements (owner {:?})",
        fixture.owner
    );
    assert_eq!(
        many, few,
        "actor=the owner's device under a credential narrowed to one facet; expected the read of a TURN of {MANY} MESSAGEs to judge the owner's exemption as often as the read of a TURN of {FEW} ({few} judgements), not once more per MESSAGE at the facet gate; seen {many}"
    );
}

#[test]
fn each_read_under_a_facet_limited_owner_credential_judges_its_exemption_again() {
    let fixture = fixture();
    let lane = fixture
        .vault
        .scoped_read(facet_limited_device_key(&fixture));
    let one = judgements_of_one_read(&lane, fixture.few_turn, "two-MESSAGE");
    let (reads, judgements) = count_owner_exemption_judgements(|| {
        [
            lane.edges_out(&fixture.few_turn),
            lane.edges_out(&fixture.few_turn),
        ]
    });
    assert!(
        reads
            .iter()
            .all(|read| matches!(read, Ok(result) if result.value.is_some())),
        "precondition: both reads retrieve the two-MESSAGE TURN"
    );
    assert_eq!(
        judgements,
        2 * one,
        "actor=the owner's device under a credential narrowed to one facet; expected each of two reads to prove the owner's exemption in its own snapshot ({one} judgements each), the verdict held for no longer than its read; seen {judgements} for both"
    );
}
