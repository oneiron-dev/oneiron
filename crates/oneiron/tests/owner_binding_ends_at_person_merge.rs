//! A co-Owner merged or split away holds no owner standing, though its owner
//! binding outlives the op (FIX OWNER-BINDING-OUTLIVES-PERSON-MERGE, Astra F1
//! on #8148).
//!
//! A merge or split keeps the PERSON row and revokes no authority binding:
//! the merge source becomes a redirect shell, the split original too, and
//! "an undo is exempt, because it revives" (ARCH-0055). The vault is shared,
//! and a PERSON other than the embedded owner is one of its Owners, whom the
//! host binds as the vault's human owner. Once that PERSON is merged into
//! another, or split into two heads, it is no live PERSON, so the live owner
//! census no longer names it: its owner verbs are refused, and an owner key
//! it held from before the op reads nothing. The survivor takes no owner
//! standing from the merge: the binding names the merged PERSON, and no
//! Owner grant moves. An undo of the merge revives the PERSON, and with it
//! the standing its binding and its Owner grant still carry, so the fix is
//! a read of liveness, not a revocation at the op.
//!
//! Closed on main by 555b68d33cd (the rooted owner arm asks the live owner
//! census after the binding), which no test of a merge or split covered.
//! Red with that commit reverted: the binding alone answered, and
//! `actor_binding_is_live_in` reads the row's deletion state, not its
//! identity lifecycle, so the merged and the split co-Owner kept their owner
//! verbs and their owner key read on. Guards: the owner verbs and the owner
//! key's read before each op, the survivor's refusal, and the undo.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_binding_ends_at_person_merge`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::ClaimError;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, ReassignmentMap, SplitOp, SurvivorshipPlan,
};
use oneiron::memory::{
    MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

/// The shared vault's id.
const SHARED: u64 = 46;

/// A shared vault with a second Owner, a PERSON other than the embedded
/// owner, whom the host binds as its human owner; that PERSON's MESSAGE; and
/// three more PERSONs: a merge's survivor and a split's two heads.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    person: EntityId,
    survivor: EntityId,
    heads: [EntityId; 2],
    message: EntityId,
}

/// An owner proof for `person`, as each owner act carries one.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )
        .expect("the PERSON lands");
    id
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // This install's signing keys sign the identity ops' engine seals (P6c).
    vault
        .prepare_install_signing()
        .expect("this install's signing keys");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
        .expect("the host binds the embedded owner");
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(FederationGrantRole::Owner),
            }],
            1,
        )
        .expect("the vault is shared, the embedded owner its Owner");
    let person = put_person(&vault);
    let survivor = put_person(&vault);
    let heads = [put_person(&vault), put_person(&vault)];
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, person)
        .expect("the embedded owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once: the PERSON is an Owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, person)
        .expect("the host binds the PERSON as the vault's human owner");
    let message = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "The spring garden needs a watering rota.".to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the PERSON's turn lands");
    Fixture {
        vault,
        _dir: dir,
        person,
        survivor,
        heads,
        message,
    }
}

/// `actor`'s owner check, the one every owner verb asks.
fn owner_verbs(fixture: &Fixture, actor: EntityId) -> MemoryResult<()> {
    fixture
        .vault
        .memory(actor, EdgeActorClass::Human)
        .verify_owner()
}

/// The bound co-Owner's own owner key: the owner's floor, which proves the
/// owner binding and the live owner census again at every read.
fn owner_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Human)
        .read_key()
        .expect("the bound co-Owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "precondition: the bound co-Owner's own key holds the owner's floor"
    );
    key
}

/// What `key` point-reads of the co-Owner's MESSAGE: `Ok(true)` when it
/// reads the row.
fn reads_message(fixture: &Fixture, key: ScopedReadActorKey) -> oneiron::Result<bool> {
    fixture
        .vault
        .scoped_read(key)
        .get_entity_parts_with_receipt(&fixture.message, None)
        .map(|read| read.value.is_some())
}

/// The owner key's read refused because its owner is no longer live.
fn owner_not_live(read: &oneiron::Result<bool>) -> bool {
    matches!(
        read,
        Err(oneiron::Error::Claim(ClaimError::ScopedReadOwnerNotLive(_)))
    )
}

/// The co-Owner holds its owner verbs and its owner key reads its MESSAGE:
/// each case's guard before the op.
fn assert_owner_before_op(fixture: &Fixture) {
    owner_verbs(fixture, fixture.person)
        .expect("precondition: the bound co-Owner holds its owner verbs");
    let read = reads_message(fixture, owner_key(fixture));
    assert!(
        matches!(read, Ok(true)),
        "precondition: the co-Owner's owner key reads its MESSAGE; got {read:?}"
    );
}

/// Merges the co-Owner into the survivor read-through, on the engine's
/// seal, and returns the merge event.
fn merge_away(fixture: &Fixture) -> EntityId {
    let outcome = fixture
        .vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![fixture.person],
                survivor: fixture.survivor,
                evidence: IdentityOpEvidence {
                    refs: vec![fixture.survivor, fixture.person],
                    rationale: "one person, two rows".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            fixture.vault.now_recorded_at(),
        )
        .expect("precondition: the merge writes");
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("precondition: the merge applies; got {outcome:?}");
    };
    assert_lifecycle(fixture, EntityLifecycleState::Merged);
    event
}

/// Splits the co-Owner into the two heads, on the engine's seal.
fn split_away(fixture: &Fixture) {
    let outcome = fixture
        .vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Split(SplitOp {
                entity: fixture.person,
                heads: fixture.heads.to_vec(),
                reassignment: ReassignmentMap::default(),
                evidence: IdentityOpEvidence {
                    refs: vec![fixture.person],
                    rationale: "two people, one row".to_owned(),
                },
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            fixture.vault.now_recorded_at(),
        )
        .expect("precondition: the split writes");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "precondition: the split applies; got {outcome:?}"
    );
    assert_lifecycle(fixture, EntityLifecycleState::Split);
}

fn assert_lifecycle(fixture: &Fixture, expected: EntityLifecycleState) {
    assert_eq!(
        fixture
            .vault
            .entity_lifecycle_state(&fixture.person)
            .expect("lifecycle read"),
        expected,
        "precondition: the co-Owner's identity lifecycle"
    );
}

/// A merged co-Owner is a redirect shell, not an owner: its binding stands,
/// and its owner verbs are refused. The survivor gains none: the merge moves
/// no binding and no Owner grant.
#[test]
fn a_merged_co_owner_holds_no_owner_verb_and_its_survivor_gains_none() {
    let fixture = fixture();
    assert_owner_before_op(&fixture);

    merge_away(&fixture);

    let refused = owner_verbs(&fixture, fixture.person);
    assert!(
        matches!(&refused, Err(error) if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "actor=the merged co-Owner; expected its owner verbs refused (OWNER_BINDING_REQUIRED: not a live Owner); got {refused:?}"
    );
    let survivor = owner_verbs(&fixture, fixture.survivor);
    assert!(
        matches!(&survivor, Err(error) if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "actor=the merge's survivor; expected no owner verb (no binding, no Owner grant); got {survivor:?}"
    );
}

/// An owner key the co-Owner held from before its merge proves its owner
/// again at the read, and reads nothing once that owner is a merged shell.
#[test]
fn a_merged_co_owners_owner_key_reads_nothing() {
    let fixture = fixture();
    assert_owner_before_op(&fixture);
    let held = owner_key(&fixture);

    merge_away(&fixture);

    let read = reads_message(&fixture, held);
    assert!(
        owner_not_live(&read),
        "actor=the merged co-Owner, owner key held from before the merge; expected ScopedReadOwnerNotLive; got {read:?}"
    );
}

/// A split original is a redirect shell to its heads, not an owner: its
/// owner verbs are refused, and an owner key it held from before the split
/// reads nothing.
#[test]
fn a_split_co_owner_holds_no_owner_verb_and_its_owner_key_reads_nothing() {
    let fixture = fixture();
    assert_owner_before_op(&fixture);
    let held = owner_key(&fixture);

    split_away(&fixture);

    let refused = owner_verbs(&fixture, fixture.person);
    assert!(
        matches!(&refused, Err(error) if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "actor=the split co-Owner; expected its owner verbs refused (OWNER_BINDING_REQUIRED: not a live Owner); got {refused:?}"
    );
    let read = reads_message(&fixture, held);
    assert!(
        owner_not_live(&read),
        "actor=the split co-Owner, owner key held from before the split; expected ScopedReadOwnerNotLive; got {read:?}"
    );
}

/// An undo revives the merged co-Owner (ARCH-0055), and its binding and its
/// Owner grant, which the merge never revoked, give it its owner standing
/// back: its owner verbs hold, and an owner key held from before the merge
/// reads its MESSAGE again.
#[test]
fn an_undone_merge_gives_the_co_owner_its_owner_standing_back() {
    let fixture = fixture();
    assert_owner_before_op(&fixture);
    let held = owner_key(&fixture);
    let event = merge_away(&fixture);

    let outcome = fixture
        .vault
        .undo_identity_topology_event(
            &event,
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            fixture.vault.now_recorded_at(),
        )
        .expect("precondition: the undo writes");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "precondition: the undo applies; got {outcome:?}"
    );
    assert_lifecycle(&fixture, EntityLifecycleState::Active);

    owner_verbs(&fixture, fixture.person)
        .expect("actor=the revived co-Owner; expected its owner verbs to hold again");
    let read = reads_message(&fixture, held);
    assert!(
        matches!(read, Ok(true)),
        "actor=the revived co-Owner, owner key held from before the merge; expected it to read the MESSAGE; got {read:?}"
    );
}
