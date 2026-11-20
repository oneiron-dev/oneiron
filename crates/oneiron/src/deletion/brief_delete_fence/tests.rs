//! [BRIEF-DELETE-RESERVATION-NEVER-RELEASED-ON-REFUSAL]: the holds on one
//! reserved id. A refused delete releases only a fence its own flight created,
//! once no other delete of the id is in flight and none linearized.

use super::*;
use crate::config::VaultConfig;
use crate::error::Error;

fn open_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn reserve<'v>(vault: &'v crate::Vault, id: &EntityId) -> BriefDeleteFence<'v> {
    let txn = vault.store.env.write_txn().expect("reservation writer");
    vault
        .store
        .brief_delete_fences
        .reserve(&vault.store, txn, id)
        .expect("reserve the id")
}

fn reserved(vault: &crate::Vault, id: &EntityId) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::share::brief_delete_reserved(&vault.store, &txn, id).expect("read the fence")
}

fn conclude(vault: &crate::Vault, fence: BriefDeleteFence<'_>, outcome: Result<()>) -> Result<()> {
    conclude_brief_delete(Some(fence), &vault.store, outcome)
}

fn refused() -> Result<()> {
    Err(Error::InvariantViolation(
        "a refusal before the delete linearized",
    ))
}

fn no_hold_left(vault: &crate::Vault) -> bool {
    vault.store.brief_delete_fences.held().is_empty()
}

/// A delete refused before it linearized releases the fence its reservation
/// created.
#[test]
fn a_refused_delete_releases_the_fence_its_flight_created() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD1; 16]).expect("id");
    let fence = reserve(&vault, &id);
    assert!(reserved(&vault, &id), "the reservation fences the id");
    assert!(conclude(&vault, fence, refused()).is_err());
    assert!(
        !reserved(&vault, &id),
        "a delete refused before it linearized releases its own fence"
    );
    assert!(no_hold_left(&vault));
}

/// A delete that returned keeps its fence, and a later refused delete of the
/// id keeps it too: that fence predates the refused delete's flight.
#[test]
fn a_refused_delete_keeps_a_fence_that_predates_its_flight() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD2; 16]).expect("id");
    let first = reserve(&vault, &id);
    conclude(&vault, first, Ok(())).expect("the first delete returned");
    assert!(
        reserved(&vault, &id),
        "a delete that returned keeps its fence"
    );
    let retry = reserve(&vault, &id);
    assert!(conclude(&vault, retry, refused()).is_err());
    assert!(
        reserved(&vault, &id),
        "a refused delete keeps a fence an earlier delete left"
    );
    assert!(no_hold_left(&vault));
}

/// Of two deletes of one id in flight, the refused first keeps the fence for
/// the second; the second, refused too, releases it.
#[test]
fn a_refused_delete_keeps_the_fence_while_another_delete_of_the_id_runs() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD3; 16]).expect("id");
    let first = reserve(&vault, &id);
    let second = reserve(&vault, &id);
    assert!(conclude(&vault, first, refused()).is_err());
    assert!(
        reserved(&vault, &id),
        "the delete still in flight keeps its fence"
    );
    assert!(conclude(&vault, second, refused()).is_err());
    assert!(
        !reserved(&vault, &id),
        "the last refused delete releases the fence the first one created"
    );
    assert!(no_hold_left(&vault));
}

/// Once a delete of the id linearized, no refused delete releases its fence.
#[test]
fn a_refused_delete_keeps_the_fence_once_a_delete_of_the_id_linearized() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD4; 16]).expect("id");
    let first = reserve(&vault, &id);
    let second = reserve(&vault, &id);
    vault.store.brief_delete_fences.settle(&id);
    assert!(conclude(&vault, first, refused()).is_err());
    assert!(conclude(&vault, second, refused()).is_err());
    assert!(reserved(&vault, &id), "a linearized delete's fence stays");
    assert!(no_hold_left(&vault));
}

/// A hold dropped unconcluded keeps the fence, and a later refused delete of
/// the id finds it predating its own flight.
#[test]
fn a_hold_dropped_unconcluded_keeps_the_fence() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD5; 16]).expect("id");
    drop(reserve(&vault, &id));
    assert!(reserved(&vault, &id), "a dropped hold keeps the fence");
    assert!(no_hold_left(&vault));
    let retry = reserve(&vault, &id);
    assert!(conclude(&vault, retry, refused()).is_err());
    assert!(reserved(&vault, &id), "no later refusal takes it");
}

/// Two refused deletes of one id end at once, both before either reaches the
/// writer: exactly one finds itself the last hold, and it releases the fence.
#[test]
fn two_refusals_ending_at_once_release_the_fence_once() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD6; 16]).expect("id");
    let mut first = reserve(&vault, &id);
    let mut second = reserve(&vault, &id);
    (first.held, second.held) = (false, false);
    let fences = &vault.store.brief_delete_fences;
    let first_is_last = fences.leave_unless_last_releasable(&id);
    let second_is_last = fences.leave_unless_last_releasable(&id);
    assert!(!first_is_last, "the first refusal leaves the other hold");
    assert!(
        second_is_last,
        "the second refusal is the last hold on a releasable row"
    );
    fences.release_last(&vault.store, &id);
    assert!(
        !reserved(&vault, &id),
        "the last of two refusals ending at once releases the fence"
    );
    assert!(no_hold_left(&vault));
}

/// A refused delete finds itself the last hold, and before it takes the
/// writer a delete of the id that holds no fence publishes: the publication
/// settles under its writer, so the refused delete keeps the fence.
#[test]
fn a_refusal_keeps_the_fence_a_publication_settled_before_its_release() {
    let (_dir, vault) = open_vault();
    let id = EntityId::from_bytes([0xD7; 16]).expect("id");
    let mut refused_delete = reserve(&vault, &id);
    refused_delete.held = false;
    let fences = &vault.store.brief_delete_fences;
    assert!(fences.leave_unless_last_releasable(&id));
    let publication = vault.store.env.write_txn().expect("publication writer");
    fences.settle(&id);
    publication.commit().expect("the publication commits");
    fences.release_last(&vault.store, &id);
    assert!(
        reserved(&vault, &id),
        "a refusal never releases a fence a publication settled"
    );
    assert!(no_hold_left(&vault));
}
