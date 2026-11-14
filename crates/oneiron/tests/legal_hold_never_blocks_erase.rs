//! A legal hold never blocks an erase, a delete or a backup expiry
//! (LEGAL-HOLD-USE = B, ARCH-0038 #legal-hold-clone-ruling): the owner's erase
//! of a held record succeeds, the record reads gone, the hold still stands
//! unlifted, and the sealed copy outlives the erase; no hold keeps backups.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test legal_hold_never_blocks_erase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::legal_hold::open_clone;
use oneiron::verbs::{
    RecordEraseConfirmRequest, RecordEraseRequest, confirm_record_erase, preview_record_erase,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A device keystore with install signing on `vault`, and its embedded
/// owner's proof.
fn owner_on(vault: &Vault) -> TestResult<(EntityId, AuthenticatedOwner)> {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    Ok((actor, owner))
}

/// An owned vault whose hold store lies outside its directory, with the
/// embedded owner's proof.
struct Fixture {
    _vault_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn fixture() -> TestResult<Fixture> {
    let vault_dir = tempfile::tempdir()?;
    let store_dir = tempfile::tempdir()?;
    let config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    let vault = Vault::open_owned(vault_dir.path(), config).map_err(at("open owned"))?;
    let (actor, owner) = owner_on(&vault)?;
    Ok(Fixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        vault,
        actor,
        owner,
    })
}

/// A PERSON row named `name` at a fresh id.
fn named_row(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name }))?;
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, &body)
        .map_err(at("put a fixture row"))?;
    Ok(id)
}

/// The owner's erase of a held PERSON succeeds: the confirm is `Ok`, the
/// record reads gone, the hold still lists unlifted, and the sealed copy
/// still holds the record's entity row. At the base 2dc78a6b the confirm
/// fails with the held refusal.
#[test]
fn owner_hold_never_refuses_the_owners_erase() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let id = named_row(vault, "held record")?;
    let hold = vault
        .place_legal_hold(&fixture.owner, vec![LegalHoldTarget::Record(id)], None)
        .map_err(at("the owner's legal hold"))?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let preview = preview_record_erase(&memory, RecordEraseRequest { record: id })
        .map_err(at("erase preview"))?;
    let outcome = confirm_record_erase(
        &memory,
        &fixture.owner,
        RecordEraseConfirmRequest {
            record: id,
            preview_digest: preview.preview_digest,
            also_same_bytes: false,
        },
    )
    .map_err(at("erase confirm"))?;
    assert!(
        outcome.first.receipt_ref.is_some(),
        "the confirmed erase wrote a receipt"
    );
    assert!(
        vault
            .get(&id)
            .map_err(at("read the erased record"))?
            .is_none(),
        "the erased record reads gone"
    );
    let standing = vault
        .legal_holds(&fixture.owner)
        .map_err(at("read the holds"))?
        .into_iter()
        .find(|standing| standing.hold_id == hold.hold_id)
        .ok_or("the hold no longer lists")?;
    assert!(
        standing.lifted_at.is_none(),
        "the hold still stands unlifted"
    );
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    assert!(
        components.iter().any(|component| {
            component.source == *id.as_bytes()
                && component.family == "entities"
                && component.key == id.as_bytes().to_vec()
        }),
        "the sealed copy still holds the record's entity row"
    );
    Ok(())
}
