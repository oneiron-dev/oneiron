//! An owner's legal hold writes a sealed copy of exactly its scope into
//! the hold store outside the vault (ARCH-0038 #legal-hold, LEGAL-HOLD-USE =
//! B as a clone): the hold row carries its captures, the `Placed` event the
//! first capture's fingerprint, and each `.clone` file opens to exactly the
//! held records. Widening copies only the added records. Without a store
//! set, or with one inside the vault, placing is refused.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test legal_hold_clone`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{LegalHoldEventKind, LegalHoldTarget};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::legal_hold::{hold_dir, open_clone};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
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
    _actor: EntityId,
    owner: AuthenticatedOwner,
}

fn fixture() -> TestResult<Fixture> {
    let vault_dir = tempfile::tempdir()?;
    let store_dir = tempfile::tempdir()?;
    let config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    let vault = Vault::open_owned(vault_dir.path(), config).map_err(at("open owned"))?;
    let (_actor, owner) = owner_on(&vault)?;
    Ok(Fixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        vault,
        _actor,
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

/// An owner's hold copies exactly its scope into the sealed store: one
/// capture, its fingerprint on the `Placed` event, one `.clone` file, and
/// components from exactly the held records, each with its entity row.
#[test]
fn an_owner_hold_copies_its_exact_scope_into_the_sealed_store() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let a = named_row(vault, "held record a")?;
    let b = named_row(vault, "held record b")?;
    let _c = named_row(vault, "unheld record c")?;
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(a), LegalHoldTarget::Record(b)],
            None,
        )
        .map_err(at("the owner's legal hold"))?;
    assert_eq!(hold.clone_captures.len(), 1, "the hold has one capture");
    let fingerprint = hold.clone_captures[0].fingerprint;
    let placed = vault
        .legal_hold_log(&fixture.owner)
        .map_err(at("read the hold log"))?
        .into_iter()
        .find(|event| event.hold_id == hold.hold_id && event.event == LegalHoldEventKind::Placed)
        .ok_or("the log has no Placed event for the hold")?;
    assert_eq!(
        placed.clone_fingerprint,
        Some(fingerprint),
        "the Placed event carries the capture's fingerprint"
    );
    let dir = hold_dir(vault, hold.hold_id).map_err(at("the hold's directory"))?;
    let clones = std::fs::read_dir(&dir)
        .map_err(at("list the hold's directory"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "clone"))
        .count();
    assert_eq!(clones, 1, "the hold keeps one .clone file");
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    let sources: BTreeSet<[u8; 16]> = components
        .iter()
        .map(|component| component.source)
        .collect();
    assert_eq!(
        sources,
        BTreeSet::from([*a.as_bytes(), *b.as_bytes()]),
        "the copy's sources are exactly the held records"
    );
    for id in [a, b] {
        assert!(
            components.iter().any(|component| {
                component.source == *id.as_bytes()
                    && component.family == "entities"
                    && component.key == id.as_bytes().to_vec()
            }),
            "the copy holds the record's entity row"
        );
    }
    Ok(())
}

/// Widening copies only the added records: a second capture whose sources
/// are exactly the added record, fingerprinted on `ScopeChanged`.
#[test]
fn widening_copies_only_the_added_records() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let a = named_row(vault, "held record a")?;
    let b = named_row(vault, "held record b")?;
    let c = named_row(vault, "widened record c")?;
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(a), LegalHoldTarget::Record(b)],
            None,
        )
        .map_err(at("the owner's legal hold"))?;
    let hold = vault
        .widen_legal_hold(
            &fixture.owner,
            hold.hold_id,
            vec![LegalHoldTarget::Record(c)],
        )
        .map_err(at("widen the hold"))?;
    assert_eq!(hold.clone_captures.len(), 2, "the widening adds a capture");
    let second = hold.clone_captures[1];
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    let added: BTreeSet<[u8; 16]> = components
        .iter()
        .filter(|component| component.capture == *second.capture.as_bytes())
        .map(|component| component.source)
        .collect();
    assert_eq!(
        added,
        BTreeSet::from([*c.as_bytes()]),
        "the second capture's sources are exactly the added record"
    );
    let changed = vault
        .legal_hold_log(&fixture.owner)
        .map_err(at("read the hold log"))?
        .into_iter()
        .find(|event| {
            event.hold_id == hold.hold_id && event.event == LegalHoldEventKind::ScopeChanged
        })
        .ok_or("the log has no ScopeChanged event for the hold")?;
    assert_eq!(
        changed.clone_fingerprint,
        Some(second.fingerprint),
        "the ScopeChanged event carries the second capture's fingerprint"
    );
    Ok(())
}

/// Placing refuses a hold store inside the vault, and refuses with none
/// set. No hold is listed after either.
#[test]
fn place_refuses_a_store_inside_the_vault() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let config = VaultConfig::device().with_legal_hold_store(vault_dir.path().join("holds-inside"));
    let vault = Vault::open_owned(vault_dir.path(), config).map_err(at("open owned"))?;
    let (_actor, owner) = owner_on(&vault)?;
    let id = named_row(&vault, "held record")?;
    let error = match vault.place_legal_hold(&owner, vec![LegalHoldTarget::Record(id)], None) {
        Ok(_) => return Err("a store inside the vault must refuse the hold".into()),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        error.contains("legal hold store"),
        "the error names the store: {error}"
    );
    assert!(
        vault
            .legal_holds(&owner)
            .map_err(at("read the holds"))?
            .is_empty(),
        "no hold stands after the refusal"
    );

    let bare_dir = tempfile::tempdir()?;
    let bare =
        Vault::open_owned(bare_dir.path(), VaultConfig::device()).map_err(at("open owned"))?;
    let (_actor, owner) = owner_on(&bare)?;
    let id = named_row(&bare, "held record")?;
    let error = match bare.place_legal_hold(&owner, vec![LegalHoldTarget::Record(id)], None) {
        Ok(_) => return Err("a missing store must refuse the hold".into()),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        error.contains("no legal hold store is set"),
        "the error names the missing store: {error}"
    );
    assert!(
        bare.legal_holds(&owner)
            .map_err(at("read the holds"))?
            .is_empty(),
        "no hold stands after the refusal"
    );
    Ok(())
}
