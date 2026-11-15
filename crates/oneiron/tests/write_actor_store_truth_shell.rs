//! A soft-deleted actor shell must not pass the writer store-truth check.
//!
//! `write_actor_store_truth_in_txn` (`authority/write_authorization.rs`)
//! says the writer names a *live* entity whose type admits its class, and
//! `verify_share_actor` (`share.rs`) checks a share issuer the same way.
//! Both read the raw entity row, and a plain delete keeps that row as a
//! header-only shell that still carries its old type byte, so a deleted
//! PERSON acting as a human used to pass both checks. Each door must now
//! refuse the shell with the same answer it gives a missing actor.
//!
//! Public paths only: `Vault::observed_write_actor` runs the store-truth
//! check (on this unrooted vault a live writer then passes, as
//! `verify_write_actor_in_txn` documents), and `Vault::create_share` runs
//! the share-issuer check before its Gate decision.

use std::collections::BTreeSet;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};

const MISSING_WRITER: &str = "writer must name a live authority-bearing entity";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// Stores one live PERSON row and returns its id.
fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("a live PERSON");
    id
}

/// Soft-deletes `id` and checks the delete left the shell this row is
/// about: no live body, but the stored header still names PERSON.
fn delete_to_shell(vault: &Vault, id: EntityId) {
    assert!(
        vault.delete_entity(&id).expect("plain delete"),
        "precondition: the live PERSON was deleted"
    );
    assert!(
        vault.is_deleted_shell(&id).expect("deleted-shell read"),
        "precondition: a plain delete leaves a deleted shell"
    );
    assert_eq!(
        vault.get_entity_type(&id).expect("shell type read"),
        Some(ENTITY_TYPE_PERSON),
        "precondition: the shell still carries its PERSON header"
    );
}

fn share(recipient: EntityId) -> Share {
    Share {
        recipient_ref: recipient,
        brief_ref: "brief:opaque-report".to_owned(),
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::new(),
        include_unscoped: true,
        status: AccessGrantStatus::Active,
        created_at: 1,
        revoked_at: None,
        expires_at: None,
        mention: None,
    }
}

#[test]
fn a_deleted_writer_is_refused_as_a_missing_writer_is() {
    let (_dir, vault) = open_vault();
    let writer_id = put_person(&vault);
    let writer = WriteActor::new(writer_id, EdgeActorClass::Human);

    let live = vault.observed_write_actor(writer);
    assert!(
        matches!(live, Ok(actor) if actor.entity_ref() == writer_id),
        "guard: a live PERSON writer passes store truth on an unrooted vault: {live:?}"
    );

    let missing =
        vault.observed_write_actor(WriteActor::new(EntityId::now(), EdgeActorClass::Human));
    assert!(
        matches!(missing, Err(Error::InvalidClaimBody(reason)) if reason == MISSING_WRITER),
        "guard: a writer the store does not hold is refused as not live: {missing:?}"
    );

    delete_to_shell(&vault, writer_id);

    let deleted = vault.observed_write_actor(writer);
    assert!(
        matches!(deleted, Err(Error::InvalidClaimBody(reason)) if reason == MISSING_WRITER),
        "a deleted shell must be refused as a missing writer is: {deleted:?}"
    );
}

#[test]
fn a_deleted_share_issuer_is_refused_as_a_missing_issuer_is() {
    let (_dir, vault) = open_vault();
    let recipient = put_person(&vault);
    let share = share(recipient);

    let missing_share = EntityId::now();
    let missing = vault.create_share(
        &missing_share,
        &WriteActor::new(EntityId::now(), EdgeActorClass::Human),
        &share,
    );
    assert!(
        matches!(missing, Err(Error::EntityNotFound)),
        "guard: a share issuer the store does not hold is not found: {missing:?}"
    );

    let issuer_id = put_person(&vault);
    delete_to_shell(&vault, issuer_id);

    let share_id = EntityId::now();
    let deleted = vault.create_share(
        &share_id,
        &WriteActor::new(issuer_id, EdgeActorClass::Human),
        &share,
    );
    assert!(
        matches!(deleted, Err(Error::EntityNotFound)),
        "a deleted shell issuer must be refused as a missing issuer is: {deleted:?}"
    );
    assert!(
        vault.get_share(&share_id).expect("read the share").is_none(),
        "no share was created for the deleted issuer"
    );
}
