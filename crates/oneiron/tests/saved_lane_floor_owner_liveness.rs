//! A saved lane rebuilt over the vault owner's own key reads no more than
//! that key does: once the owner's binding lapses, it reads nothing (FIX
//! SAVED-LANE-MEET-DROPS-OWNER-LIVENESS, Astra F2 on #8061).
//!
//! The vault is shared, and a PERSON other than the embedded owner is one of
//! its Owners, whom the host binds as the vault's human owner. That PERSON
//! witnesses a MESSAGE that names no relationship. Its ungated principal
//! key, held to the base world, saves its lane: the lane
//! keeps a grant basis with no owner standing. Rebuilt over the PERSON's own
//! owner key, the lane takes that key's floor away (the meet keeps a floor
//! only under a floor's basis). The owner key re-proves its owner binding at
//! every read and reads nothing once the host binds another actor; the
//! rebuilt key carried no owner, so no read proved that binding, and it read
//! on as an ordinary ungated human key. It now keeps the binding of the
//! floor it lost and proves it at every read, whether it was rebuilt after
//! the binding lapsed or before it and held past it. While the binding
//! holds, the rebuilt lane still reads the MESSAGE.
//!
//! Only such an Owner's floor proves a binding. The live owner census of a
//! personal vault names the embedded owner alone, so a PERSON the host binds
//! there holds no floor; and the embedded owner's own floor asks the census,
//! not the binding (`embedded_owner_shortcut_holds_in_txn`), so it outlives
//! a rebind. The first form of this file bound a PERSON on a personal vault,
//! and every case stopped at the owner key's precondition (FIX
//! FLOOR-OWNER-LIVENESS-TEST-FIXTURE-PRECONDITION).
//!
//! Red on 41a670f4677, the fix's base, with this file: both rebuilt lanes
//! read the MESSAGE after the binding lapsed. Guard: the rebuilt lane's read
//! while the binding holds.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_lane_floor_owner_liveness`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WorldAuthoritySet};
use serde_json::json;

/// The shared vault's id.
const SHARED: u64 = 46;

/// A shared vault with a second Owner, a PERSON other than the embedded
/// owner, whom the host binds as its human owner, and that PERSON's MESSAGE
/// that names no relationship.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    person: EntityId,
    message: EntityId,
}

/// An owner proof for `person`, as each owner act carries one.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
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
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )
        .expect("the PERSON lands");
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
        issuer,
        person,
        message,
    }
}

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// The bound PERSON's own owner key: the owner's floor, which proves the
/// owner binding again at every read.
fn owner_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = fixture
        .vault
        .memory(fixture.person, EdgeActorClass::Human)
        .read_key()
        .expect("the bound owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "precondition: the bound PERSON's own key holds the owner's floor"
    );
    key
}

/// The bound PERSON's ungated principal key, held to the base world, saved
/// as a saved question's lane is and read back from its stored MessagePack
/// form: a lane with a grant basis and no owner standing.
fn saved_lane(fixture: &Fixture) -> FrozenReadLane {
    let key = ScopedReadActorKey::with_actor_class(fixture.person.to_hex(), "human")
        .expect("the PERSON's ungated principal key");
    assert!(
        !key.reads_as_vault_owner(),
        "precondition: the ungated principal key holds no owner floor"
    );
    let frozen = fixture
        .vault
        .scoped_read(key)
        .within_worlds(
            WorldAuthoritySet::new(true, std::iter::empty::<EntityId>())
                .expect("the base world alone"),
        )
        .freeze()
        .expect("the bounded ungated lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    let frozen: FrozenReadLane = rmp_serde::from_slice(&stored).expect("frozen lane decodes");
    assert!(
        !frozen.reads_as_principal(),
        "precondition: the base-world bound keeps the saved lane from reading as its principal's own"
    );
    frozen
}

/// Ends the bound PERSON's owner binding: the host key holds one live
/// binding, so binding another actor unbinds the owner
/// (`test_support::bind_host_actor`). The PERSON stays an Owner by the
/// census; only its binding lapses.
fn end_owner_binding(fixture: &Fixture) {
    oneiron::test_support::bind_host_actor(
        &fixture.vault,
        &fixture.issuer,
        EntityId::now(),
        "agent",
    )
    .expect("the host binds another actor in the owner's place");
}

/// While the owner binding holds, the lane rebuilt over the owner's own key
/// reads the owner's MESSAGE, as the saved key did.
#[test]
fn a_saved_lane_over_a_bound_owners_key_reads_the_owners_message() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture);
    let rebuilt = frozen
        .narrow(&fixture.vault, owner_key(&fixture))
        .expect("the saved lane rebuilds over the owner's key");
    assert!(
        !rebuilt.reads_as_vault_owner(),
        "precondition: the saved basis takes the owner's floor away"
    );
    let (read, seen) = reads(&fixture.vault.scoped_read(rebuilt), fixture.message);
    assert!(
        read,
        "actor=the bound owner, saved lane over their own key while bound; expected the MESSAGE; seen {seen}"
    );
}

/// The owner's key kept from before its binding lapsed reads nothing after;
/// the saved lane rebuilt over it after the lapse reads nothing either.
#[test]
fn a_saved_lane_rebuilt_over_a_kept_owner_key_reads_nothing_after_the_owner_binding_ends() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture);
    let kept = owner_key(&fixture);
    end_owner_binding(&fixture);
    let (floor_read, floor_seen) = reads(&fixture.vault.scoped_read(kept.clone()), fixture.message);
    assert!(
        !floor_read,
        "precondition: the owner's kept key reads nothing once its binding ends; seen {floor_seen}"
    );
    let seen = match frozen.narrow(&fixture.vault, kept) {
        Ok(rebuilt) => reads(&fixture.vault.scoped_read(rebuilt), fixture.message),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        !seen.0,
        "actor=the unbound owner, saved lane rebuilt over their kept key after the binding ended; expected no MESSAGE (the floor key reads none); seen {}",
        seen.1
    );
}

/// The saved lane rebuilt over the owner's key while the binding held, and
/// held past its end, reads nothing from then on.
#[test]
fn a_saved_lane_rebuilt_while_the_owner_is_bound_reads_nothing_after_the_owner_binding_ends() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture);
    let rebuilt = frozen
        .narrow(&fixture.vault, owner_key(&fixture))
        .expect("the saved lane rebuilds over the owner's key");
    let lane = fixture.vault.scoped_read(rebuilt);
    let (before, before_seen) = reads(&lane, fixture.message);
    assert!(
        before,
        "precondition: the rebuilt lane reads the MESSAGE while the owner is bound; seen {before_seen}"
    );
    end_owner_binding(&fixture);
    let (after, after_seen) = reads(&lane, fixture.message);
    assert!(
        !after,
        "actor=the unbound owner, saved lane rebuilt while bound and held past the binding's end; expected no MESSAGE; seen {after_seen}"
    );
}
