//! The owner's amend of an org setup records his act (RULING
//! ORG-ADMIN-AMEND-CONFIRM-RECEIPT = A, Engine 16 Nov 02:27): an `OwnerAct`
//! of kind `org_admin_amend` on the organization, in the write that changed
//! the setup, with the Admins and powers the amend added and took away,
//! read back by `Vault::org_admin_amend_acts`. An amend equal to the stored
//! setup records nothing. The amend's direction is the setup's own
//! comparator's (`OrgAdminPolicy::direction_from`): seating an Admin or
//! adding a power widens; unseating and dropping narrows.
//!
//! The reader and the comparator are new, so on the base (#8439) this file
//! does not build.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_admin_amend_receipt`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, OwnerActKind};
use oneiron::federation::{OrgAdminChange, OrgAdminPolicy, OrgAdminPower};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_authority::authority::Direction;
use serde_json::{Value, json};

/// A vault this process owns, with its embedded owner bound to the host key,
/// so the owner verbs answer the embedded owner on it (as
/// `org_admin_setup_policy`'s owned vault).
fn owned_vault(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = Vault::open_owned(dir, VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    (vault, owner)
}

fn setup(org: EntityId, admins: &[EntityId], powers: &[OrgAdminPower]) -> OrgAdminPolicy {
    OrgAdminPolicy::new(
        org,
        admins.iter().copied().collect(),
        powers.iter().copied().collect(),
    )
    .expect("a well-formed setup")
}

/// The owner's amend through the verb, as the embedded owner.
fn amend(vault: &Vault, owner: EntityId, policy: &OrgAdminPolicy) -> Value {
    let input = json!({ "policy": serde_json::to_value(policy).expect("the policy as JSON") });
    oneiron::task_verb::sdk::invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        "vault.org_admin.amend",
        input,
    )
    .expect("the owner's amend lands")
}

#[test]
fn an_amend_records_the_owners_act_with_what_it_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(dir.path());
    let (org, admin, named) = (EntityId::now(), EntityId::now(), EntityId::now());
    let stored = setup(org, &[admin], &[OrgAdminPower::AddMember]);
    vault
        .configure_org_admin(&stored)
        .expect("the owner's setup is stored");
    let widened = setup(
        org,
        &[named],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    );
    assert_eq!(widened.direction_from(&stored), Direction::Widens);

    amend(&vault, owner, &widened);
    let again = amend(&vault, owner, &widened);
    assert_eq!(again["amended"], json!(false), "{again}");

    let receipts = vault.org_admin_amend_acts().expect("the receipts read");
    assert_eq!(
        receipts.len(),
        1,
        "one receipt per changing amend: {receipts:?}"
    );
    let receipt = &receipts[0];
    assert_eq!(receipt.act.act, OwnerActKind::OrgAdminAmend);
    assert_eq!(receipt.act.owner, owner);
    assert_eq!(receipt.act.target, org);
    assert_eq!(receipt.act.surface, ActSurface::ThisInstall);
    assert_eq!(receipt.act.seen, [0; 32]);
    assert_eq!(
        receipt.change,
        OrgAdminChange {
            added_admins: BTreeSet::from([named]),
            removed_admins: BTreeSet::from([admin]),
            added_powers: BTreeSet::from([OrgAdminPower::AssignRole]),
            dropped_powers: BTreeSet::new(),
        }
    );
    assert_eq!(receipt.change.direction(), Direction::Widens);
}

#[test]
fn a_narrowing_amend_is_recorded_as_a_narrowing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(dir.path());
    let (org, admin, named) = (EntityId::now(), EntityId::now(), EntityId::now());
    let stored = setup(
        org,
        &[admin, named],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    );
    vault
        .configure_org_admin(&stored)
        .expect("the owner's setup is stored");
    let narrowed = setup(org, &[admin], &[OrgAdminPower::AddMember]);
    assert_eq!(narrowed.direction_from(&stored), Direction::Narrows);

    amend(&vault, owner, &narrowed);

    let receipts = vault.org_admin_amend_acts().expect("the receipts read");
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_eq!(
        receipts[0].change,
        OrgAdminChange {
            added_admins: BTreeSet::new(),
            removed_admins: BTreeSet::from([named]),
            added_powers: BTreeSet::new(),
            dropped_powers: BTreeSet::from([OrgAdminPower::AssignRole]),
        }
    );
    assert_eq!(receipts[0].change.direction(), Direction::Narrows);
}
