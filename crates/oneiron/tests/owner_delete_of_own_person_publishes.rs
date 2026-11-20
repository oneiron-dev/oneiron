//! The vault owner's soft delete of their own PERSON publishes its tombstone
//! (FIX MEMORY-DELETE-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT, review round 1
//! P1 of #9608). The owner door re-proves the owner's proof in the publish
//! transaction, after the delete's own scrub committed and left that PERSON
//! a deleted shell; the publication then takes that PERSON as live, as the
//! gated delete re-proves an owner deleting itself (L9-52 (b)).
//!
//! Red at #9608's head 6c634d1295de: the publication re-proves the owner as
//! a live person and refuses `ConsentOwnerNotAuthenticated` after the local
//! scrub committed. A PERSON another request deleted is never taken as live:
//! that owner's delete is refused before it scrubs, on both heads.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! owner_delete_of_own_person_publishes`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

fn open(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    // A delete signs its receipt with this install's key.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// An unrooted shared vault whose roster holds its embedded owner and a
/// second person as Owners, the second having accepted its founding
/// invitation; returns that second Owner. No door binds a `human` actor on
/// an unrooted vault, so the last-bound-owner guard lets an Owner delete
/// their own PERSON while the other Owner stays.
fn co_owner(vault: &Vault) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let co_owner = EntityId::now();
    vault
        .put_entity(
            &co_owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: co_owner,
                    role: Some(Role::Owner),
                },
            ],
            1,
        )
        .expect("a shared vault with two owners");
    let co_owner_proof = proof(vault, co_owner);
    let invitation = vault
        .shared_invitations(&co_owner_proof, SHARED)
        .expect("the co-owner's invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the co-owner's founding invitation");
    vault
        .accept_shared_invitation(&co_owner_proof, SHARED, &invitation.id)
        .expect("the co-owner accepts");
    co_owner
}

#[test]
fn an_owner_soft_delete_of_their_own_person_publishes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let co_owner = co_owner(&vault);

    let deleted = vault.delete_entity_with_reason_as_owner(
        &proof(&vault, co_owner),
        &co_owner,
        DeleteReason::UserDelete,
    );

    let outcome = deleted.expect(
        "the owner's delete of their own PERSON publishes after the shell its own scrub left",
    );
    assert!(outcome.existed, "the co-owner's PERSON row existed");
    assert!(
        vault.is_deleted_shell(&co_owner).expect("shell read"),
        "the co-owner's PERSON is a deleted shell"
    );
}

#[test]
fn an_owner_whose_person_another_request_deleted_deletes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let co_owner = co_owner(&vault);
    let stale = proof(&vault, co_owner);
    vault
        .delete_entity(&co_owner)
        .expect("another request deletes the co-owner's PERSON");

    let refused =
        vault.delete_entity_with_reason_as_owner(&stale, &co_owner, DeleteReason::UserHardDelete);

    assert!(
        refused.is_err(),
        "a proof whose PERSON another request deleted is taken as live: {refused:?}"
    );
    assert!(
        vault.is_deleted_shell(&co_owner).expect("shell read"),
        "the other request's soft delete stands and nothing purged the shell"
    );
}
