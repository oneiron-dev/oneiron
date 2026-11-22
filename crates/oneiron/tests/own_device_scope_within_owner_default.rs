//! An own-device Grant confers no more than the vault's Owner default (FIX
//! OWN-DEVICE-ROW-SCOPE-NOT-BOUND-BY-OWNER-DEFAULT; review #9068 P2-1).
//!
//! No act gives an own-device Grant (pass 28 R4): the pairing door provisions it with the
//! vault's Owner default, and it stands as derived while its holder is a live Owner. Before
//! this fix the derived read took the row's authority scope as stored, so a writer on the
//! own-device lane that put the row back with a top scope widened every device whose selector
//! names it past the owner's narrowed default: the selector export filter bounds each record by
//! the conferred Grant's scope. Now the read meets the stored scope with the Owner default the
//! vault resolves at the read, so the owner's narrowing also reaches a device paired before it,
//! and a row the default leaves nothing, or a vault whose policy resolves no Owner default,
//! confers nothing.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test own_device_scope_within_owner_default`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset as Preset, FederationGrantRole as Role, Scope,
    ScopeAxis, ScopeId, own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron::store::GateDecisionId;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, authorize_sync_selector};
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::grant_standing::selector_export_scope;
use oneiron::test_doors::steward::empty_grant_policy_rows;
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A fresh personal vault whose install carries acts, and its owner.
fn carrier_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (_issuer, owner) = provision_act_carrier(&vault);
    (dir, vault, owner)
}

fn world_axis(worlds: &[EntityId]) -> ScopeAxis<ScopeId> {
    worlds.iter().map(|world| ScopeId(*world)).collect()
}

/// The owner narrows the vault's Owner role default to the worlds `worlds`, through the
/// owner's policy door; every other policy row stays as seeded.
fn narrow_owner_default(vault: &Vault, owner: EntityId, worlds: &[EntityId]) {
    let ids = vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("the policy manifests");
    assert_eq!(
        ids.len(),
        1,
        "FIXTURE: a fresh vault has one seeded policy manifest"
    );
    let id = ids[0];
    let mut manifest: serde_json::Value = rmp_serde::from_slice(
        &vault
            .get(&id)
            .expect("the policy read")
            .expect("the seeded policy"),
    )
    .expect("decode the seeded policy");
    let row = manifest["federation_grant_rows"]
        .as_array_mut()
        .expect("FIXTURE: the grant policy rows")
        .iter_mut()
        .find(|row| row["kind"] == "role_default" && row["role"] == "owner")
        .expect("FIXTURE: the Owner role default");
    let mut scope: Scope =
        serde_json::from_value(row["scope"].clone()).expect("the Owner default scope");
    scope.worlds = world_axis(worlds);
    row["scope"] = serde_json::to_value(scope).expect("the Owner default scope");
    vault
        .install_owner_policy_manifest(
            &proof(vault, owner),
            id,
            rmp_serde::to_vec_named(&manifest).expect("encode the policy"),
            vault.now_recorded_at(),
        )
        .expect("the owner narrows the Owner default");
}

/// An own-device row for `holder` in the pairing door's shape, put with no act, whose
/// authority scope is `scope`: its id.
fn own_device_row(vault: &Vault, holder: EntityId, scope: Scope) -> EntityId {
    let mut grant = FederationGrant::new(
        own_device_residence_scope(),
        holder,
        Role::Owner,
        Preset::Owner,
    );
    grant.authority_scope = scope;
    let id = EntityId::now();
    put_unkeyed_member_grant(vault, id, &grant).expect("the row lands");
    id
}

fn scope_in(worlds: &[EntityId]) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = world_axis(worlds);
    scope
}

/// The worlds the selector export filter bounds the records of Grant `id` by.
fn exported_worlds(vault: &Vault, id: EntityId) -> ScopeAxis<ScopeId> {
    selector_export_scope(vault, id)
        .expect("the owner's own-device row backs the export filter")
        .worlds
}

/// Whether the residence selector under Grant `grant`, held by `holder`, is authorized.
fn residence_selector_authorized(vault: &Vault, grant: EntityId, holder: EntityId) -> bool {
    let selector = SyncSelector::new(
        grant,
        holder,
        SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    );
    authorize_sync_selector(vault, own_device_residence_scope(), &selector).is_ok()
}

/// The review's case: the owner narrows the Owner default, then a writer on the own-device
/// lane puts the owner's own-device row back with a top scope.
#[test]
fn an_own_device_row_put_back_with_a_top_scope_exports_only_the_narrowed_default() {
    let (_dir, vault, owner) = carrier_vault();
    let kept = EntityId::now();
    narrow_owner_default(&vault, owner, &[kept]);
    let id = own_device_row(&vault, owner, Scope::top());

    assert_eq!(
        exported_worlds(&vault, id),
        world_axis(&[kept]),
        "an own-device row confers no world the owner's default leaves out"
    );
}

#[test]
fn a_device_paired_before_the_owner_narrows_the_default_exports_the_narrowed_default() {
    let (_dir, vault, owner) = carrier_vault();
    // The shipped Owner default is the top scope, so this is the row pairing provisions.
    let id = own_device_row(&vault, owner, Scope::top());
    let kept = EntityId::now();
    narrow_owner_default(&vault, owner, &[kept]);

    assert_eq!(
        exported_worlds(&vault, id),
        world_axis(&[kept]),
        "the owner's narrowing of his default reaches a device paired before it"
    );
}

#[test]
fn an_own_device_row_the_default_leaves_no_world_backs_no_selector() {
    let (_dir, vault, owner) = carrier_vault();
    narrow_owner_default(&vault, owner, &[EntityId::now()]);
    let id = own_device_row(&vault, owner, scope_in(&[EntityId::now()]));

    assert!(
        !residence_selector_authorized(&vault, id, owner),
        "an own-device row whose worlds meet the owner's default in none confers nothing"
    );
}

#[test]
fn an_own_device_row_backs_no_selector_when_no_owner_default_resolves() {
    let (_dir, vault, owner) = carrier_vault();
    let id = own_device_row(&vault, owner, Scope::top());
    assert!(
        residence_selector_authorized(&vault, id, owner),
        "FIXTURE: the row backs the owner's selector under the shipped policy"
    );
    empty_grant_policy_rows(&vault).expect("the grant policy rows emptied");

    assert!(
        !residence_selector_authorized(&vault, id, owner),
        "with no Owner default the pairing door provisions nothing, and no own-device row confers"
    );
}

/// Guard: the read is a meet, not the default put in the row's place: a row narrower than the
/// owner's default keeps its own worlds.
#[test]
fn an_own_device_row_narrower_than_the_default_keeps_its_own_worlds() {
    let (_dir, vault, owner) = carrier_vault();
    let (kept, other) = (EntityId::now(), EntityId::now());
    narrow_owner_default(&vault, owner, &[kept, other]);
    let id = own_device_row(&vault, owner, scope_in(&[kept]));

    assert_eq!(
        exported_worlds(&vault, id),
        world_axis(&[kept]),
        "an own-device row within the default exports its own worlds"
    );
}

/// Guard: under the shipped default (the top scope) the owner's own-device row exports what
/// it holds.
#[test]
fn the_owners_own_device_row_exports_its_worlds_under_the_shipped_default() {
    let (_dir, vault, owner) = carrier_vault();
    let id = own_device_row(&vault, owner, Scope::top());

    assert_eq!(
        exported_worlds(&vault, id),
        ScopeAxis::All,
        "the shipped Owner default leaves the owner's own-device row whole"
    );
}
