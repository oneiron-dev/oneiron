//! A batch ref check under a narrower owner credential judges the owner's
//! relationship exemption once per call, not once per ref it names (FIX
//! REFS-READABLE-EACH-FRESH-AUTHORITY-PER-ROW).
//!
//! `ScopedRead::refs_readable_each` and `ScopedRead::all_refs_readable`
//! judge every ref in one snapshot, but each ref built its own held
//! authority (`HeldAuthority::for_request(None)` per id): each ref loaded
//! its own relationship context and proved the owner's exemption again
//! (`owner_exemption_holds_in_txn`, whose liveness test folds the identity
//! lifecycle). A call over R refs paid R proofs. The call now holds one
//! authority for all its refs, as a search holds one for its hits (FIX
//! 7462), so every ref of the call shares one verdict.
//!
//! Fixture as in `tests/owner_exemption_judged_once_per_read.rs`: the
//! owner's device credential, narrowed by the device itself, holds the
//! owner's exemption below the owner's floor. It names the MESSAGEs of two
//! TURNs, of two and of eight MESSAGEs, each MESSAGE in its own
//! relationship that no PERSON is a member of and no grant names, so each
//! ref meets the relationship gate under that exemption. A test door counts
//! the exemption judgements (`test_doors::owner_exemption_judgements`); a
//! call over eight refs must cost no more of them than a call over two.
//!
//! Expected red on main 0aedc807c52, by reading (not run before READY): the
//! eight-ref calls judge the exemption six more times than the two-ref
//! calls, once per ref. Guard:
//! `each_ref_check_under_an_owner_credential_judges_its_exemption_again`,
//! the verdict never outlives its call.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test refs_readable_owner_exemption_once_per_call`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{ScopedRead, ScopedReadActorKey};
use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_exemption_judgements::count_owner_exemption_judgements;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:refs-readable-owner-exemption-once-per-call";
/// The binding key seed of the owner's own human-class device.
const DEVICE_BINDING_SEED: u8 = 0x7E;
/// The caveat that narrows only the device credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;
/// The MESSAGEs of the small TURN.
const FEW: usize = 2;
/// The MESSAGEs of the large TURN.
const MANY: usize = 8;

/// A vault whose owner paired a human-class device on their own PERSON and
/// witnessed two TURNs, of `FEW` and `MANY` MESSAGEs, each MESSAGE in its own
/// relationship that no PERSON is a member of and no grant names.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    device_slip: CapabilitySlip,
    few: Vec<EntityId>,
    many: Vec<EntityId>,
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
    let few = witness_relationship_messages(&vault, owner, FEW);
    let many = witness_relationship_messages(&vault, owner, MANY);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        device_slip,
        few,
        many,
    }
}

/// The MESSAGEs of `author`'s TURN of `messages` MESSAGEs, witnessed as the
/// human it is, each in its own relationship no PERSON is a member of and no
/// grant names.
fn witness_relationship_messages(
    vault: &Vault,
    author: EntityId,
    messages: usize,
) -> Vec<EntityId> {
    let written = (0..messages)
        .map(|order| WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".to_owned(),
            content: format!("The orchard rota note number {order}."),
            parts: None,
            metadata: Some(json!({ "rel": EntityId::now().to_hex() })),
            is_visible: true,
            order: u32::try_from(order).expect("a small order"),
            quote: None,
        })
        .collect();
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 1,
            messages: written,
            assertions: Default::default(),
        })
        .expect("the author's turn lands");
    let ids: Vec<EntityId> = receipt
        .messages
        .iter()
        .map(|message| EntityId::from_hex(&message.id).expect("a written MESSAGE's id"))
        .collect();
    assert_eq!(
        ids.len(),
        messages,
        "precondition: the witness receipt names every written MESSAGE"
    );
    ids
}

/// The device credential narrowed by the device itself, proved by its key
/// and kept on its read key: a human-class key below the owner's floor,
/// holding the owner's exemption (`credential_read_key`).
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
    let proof = verified(fixture, &slip);
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("the credential's read key")
        .expect("the credential grants read");
    assert!(
        key.actor_class() == Some("human") && !key.reads_as_vault_owner(),
        "precondition: the device's attenuated credential reads as a human, below the owner's floor; seen class {:?}",
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

/// The owner exemption judgements one `refs_readable_each` call over `sets`
/// makes under `lane`, once the call is shown to resolve every set whole.
fn judgements_of_refs_readable_each(
    lane: &ScopedRead<'_>,
    sets: &[Vec<EntityId>],
    name: &str,
) -> usize {
    let (each, judgements) = count_owner_exemption_judgements(|| lane.refs_readable_each(sets));
    assert!(
        matches!(&each, Ok(each) if each.len() == sets.len() && each.iter().all(|whole| *whole)),
        "precondition: the owner's attenuated device credential resolves every ref of {name}, each a MESSAGE in a relationship the owner holds no grant in; seen {each:?}"
    );
    judgements
}

/// The owner exemption judgements one `all_refs_readable` call over `ids`
/// makes under `lane`, once the call is shown to resolve them all.
fn judgements_of_all_refs_readable(lane: &ScopedRead<'_>, ids: &[EntityId], name: &str) -> usize {
    let (all, judgements) = count_owner_exemption_judgements(|| lane.all_refs_readable(ids));
    assert!(
        matches!(all, Ok(true)),
        "precondition: the owner's attenuated device credential resolves every ref of {name}, each a MESSAGE in a relationship the owner holds no grant in; seen {all:?}"
    );
    judgements
}

#[test]
fn refs_readable_each_judges_the_owner_exemption_once_per_call_however_many_refs_it_names() {
    let fixture = fixture();
    let lane = fixture.vault.scoped_read(attenuated_device_key(&fixture));
    let few = judgements_of_refs_readable_each(
        &lane,
        std::slice::from_ref(&fixture.few),
        "the two-MESSAGE set",
    );
    let many = judgements_of_refs_readable_each(
        &lane,
        std::slice::from_ref(&fixture.many),
        "the eight-MESSAGE set",
    );
    let both = judgements_of_refs_readable_each(
        &lane,
        &[fixture.few.clone(), fixture.many.clone()],
        "both sets",
    );
    assert!(
        few >= 1,
        "precondition: a ref check under the owner's narrower credential proves the owner's exemption in its own snapshot; seen {few} judgements (owner {:?})",
        fixture.owner
    );
    assert_eq!(
        (many, both),
        (few, few),
        "actor=the owner's device under an attenuated credential; expected refs_readable_each over {MANY} relationship MESSAGEs, and over both sets in one call, to judge the owner's exemption as often as over {FEW} ({few} judgements), not once more per ref; seen {many} for {MANY} refs and {both} for both sets"
    );
}

#[test]
fn all_refs_readable_judges_the_owner_exemption_once_per_call_however_many_refs_it_names() {
    let fixture = fixture();
    let lane = fixture.vault.scoped_read(attenuated_device_key(&fixture));
    let few = judgements_of_all_refs_readable(&lane, &fixture.few, "the two-MESSAGE set");
    let many = judgements_of_all_refs_readable(&lane, &fixture.many, "the eight-MESSAGE set");
    assert!(
        few >= 1,
        "precondition: a ref check under the owner's narrower credential proves the owner's exemption in its own snapshot; seen {few} judgements (owner {:?})",
        fixture.owner
    );
    assert_eq!(
        many, few,
        "actor=the owner's device under an attenuated credential; expected all_refs_readable over {MANY} relationship MESSAGEs to judge the owner's exemption as often as over {FEW} ({few} judgements), not once more per ref; seen {many}"
    );
}

#[test]
fn each_ref_check_under_an_owner_credential_judges_its_exemption_again() {
    let fixture = fixture();
    let lane = fixture.vault.scoped_read(attenuated_device_key(&fixture));
    let sets = std::slice::from_ref(&fixture.few);
    let one = judgements_of_refs_readable_each(&lane, sets, "the two-MESSAGE set");
    let (calls, judgements) = count_owner_exemption_judgements(|| {
        [lane.refs_readable_each(sets), lane.refs_readable_each(sets)]
    });
    assert!(
        calls
            .iter()
            .all(|each| matches!(each, Ok(each) if each.as_slice() == [true])),
        "precondition: both calls resolve the two-MESSAGE set whole; seen {calls:?}"
    );
    assert_eq!(
        judgements,
        2 * one,
        "actor=the owner's device under an attenuated credential; expected each of two refs_readable_each calls to prove the owner's exemption in its own snapshot ({one} judgements each), the verdict held for no longer than its call; seen {judgements} for both"
    );
}
