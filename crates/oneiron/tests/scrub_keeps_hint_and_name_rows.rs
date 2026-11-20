//! FIX-LIST L25253 [SCRUB-KEEPS-HINT-AND-NAME-ROWS]: every erase scrubs the
//! body to a shell in place first, and the GDPR/policy purge's later deindex
//! reads the shell, so it found no identity hint or name and deleted nothing.
//! The scrub write itself moves both indexes now, so an erase (a GDPR, policy
//! or user delete) leaves no identity-hint digest row naming the erased
//! PERSON and no `named_entity:v1:` row naming the erased SESSION, at once or
//! after a reopen.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test scrub_keeps_hint_and_name_rows`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::scrub_keeps_hint_and_name_rows as doors;
use oneiron::{DeleteReason, EntityId, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

fn put_person(vault: &Vault, id: &EntityId, name: &str) {
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("a person body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("a PERSON row");
}

fn put_session(vault: &Vault, id: &EntityId, relationship: &EntityId) {
    let body = Value::Map(vec![(
        Value::from("rel"),
        Value::Binary(relationship.as_bytes().to_vec()),
    )]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &body).expect("a session body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_SESSION,
            TimeRange { start: 1, end: 1 },
            1,
            &data,
        )
        .expect("a SESSION row");
}

fn open_vault(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    // An erase signs its receipt: install this device's keystore, as a host
    // does after each open.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
}

#[test]
fn an_erase_leaves_no_identity_hint_row_naming_the_erased_person() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let indexed = |vault: &Vault, person: EntityId| {
        doors::identity_hint_rows(vault)
            .expect("index rows")
            .iter()
            .any(|(_, _, id)| *id == person)
    };
    let mut erased = Vec::new();
    for (n, reason) in [
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
        DeleteReason::UserDelete,
    ]
    .into_iter()
    .enumerate()
    {
        let person = EntityId::now();
        put_person(&vault, &person, &format!("Erased Person {n}"));
        assert!(indexed(&vault, person), "the name write indexes it");
        vault
            .delete_entity_with_reason(&person, reason)
            .expect("erase");
        assert!(
            !indexed(&vault, person),
            "{reason:?} leaves no hint row naming the PERSON"
        );
        erased.push(person);
    }
    // Nothing rebuilds the index at open, so the reopen keeps the rows as
    // the erases left them.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    for person in erased {
        assert!(!indexed(&vault, person), "the reopen keeps no row for it");
    }
}

#[test]
fn an_erase_leaves_no_named_entity_row_naming_the_erased_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("an owner");
    let indexed = |vault: &Vault, session: EntityId| {
        doors::named_entity_rows(vault)
            .expect("index rows")
            .iter()
            .any(|key| key.ends_with(session.as_bytes()))
    };
    let mut erased = Vec::new();
    for reason in [
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
        DeleteReason::UserDelete,
    ] {
        let session = EntityId::now();
        put_session(&vault, &session, &owner);
        assert!(indexed(&vault, session), "the rel write indexes it");
        vault
            .delete_entity_with_reason(&session, reason)
            .expect("erase");
        assert!(
            !indexed(&vault, session),
            "{reason:?} leaves no named-entity row naming the SESSION"
        );
        erased.push(session);
    }
    // Nothing rebuilds the index at open, so the reopen keeps the rows as
    // the erases left them.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    for session in erased {
        assert!(!indexed(&vault, session), "the reopen keeps no row for it");
    }
}
