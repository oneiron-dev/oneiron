//! A selector narrowed to some facets or bands carries the hard delete of a
//! row in them (SELECTOR-FACET-BAND-EXPORT-DROPS-BODYLESS-TOMBSTONES).
//!
//! A hard delete takes the row's body out of the vault's own window in the
//! same commit, so a selector export keeps no row of it, and the delete
//! travels only through the tombstone rule for rows it does not keep
//! (`sync/selector/tombstones.rs`). Before this fix that rule carried nothing
//! once the selector named a facet or a band, so a peer whose selector names
//! facets or bands never learned of the delete and kept the deleted row.
//! #9592 fixed only the world axis of the same rule
//! (`tests/residence_tombstone_answer.rs`, whose world-selector fixture this
//! file follows).
//!
//! A member P holds a live Member federation grant whose Scope admits every
//! record. The owner keeps a CLAIM about P in the vault's default facet,
//! packs and keeps the window, and hard-deletes the CLAIM. P's band-narrowed
//! selector (the CLAIM's band) and facet-narrowed selector (the CLAIM's
//! facet) then carry its tombstone; a selector narrowed to another band or
//! another facet does not.
//!
//! Each `FIXTURE:` assertion checks the setup, never the export rule.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_facet_band_tombstone_after_hard_delete`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use loro::{ExportMode, LoroDoc};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SelectorRange, selector_range_of,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, TypeByteFamily};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EntityId, Vault, VaultConfig,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

/// The shared vault the federation grant names.
const SHARED_VAULT_ID: u64 = 7;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// Keeps `doc` as the vault's own window `key`, as the engine persists a
/// window: its snapshot and version vector.
fn persist_window(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    let window = key.as_str();
    vault
        .sync_state_put(
            &format!("d:w:{window}"),
            &doc.export(ExportMode::Snapshot).expect("window snapshot"),
        )
        .expect("FIXTURE: the window snapshot is kept");
    vault
        .sync_state_put(&format!("sv:w:{window}"), &doc.oplog_vv().encode())
        .expect("FIXTURE: the window version is kept");
    vault
        .sync_state_put(&format!("svf:w:{window}"), &[1_u8])
        .expect("FIXTURE: the window version flag is kept");
}

/// Whether each of the member's selector exports carried the deleted
/// CLAIM's tombstone.
struct Carried {
    /// No facet, band or world filter.
    open: bool,
    /// Narrowed to the CLAIM's band.
    own_band: bool,
    /// Narrowed to a band that does not hold the CLAIM.
    other_band: bool,
    /// Narrowed to the CLAIM's facet.
    own_facet: bool,
    /// Narrowed to a facet that does not hold the CLAIM.
    other_facet: bool,
}

/// Gives the member a live Member grant whose Scope admits every record,
/// keeps a CLAIM about the member in the default facet in the vault's
/// window, hard-deletes it, and exports the window that is left through each
/// of the member's selectors.
fn exports_after_hard_delete() -> Carried {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // The delete signs as this install first, so the vault needs the
    // keystore a host installs after each open.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
        )
        .expect("a member");
    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");

    let facet = vault
        .default_facet()
        .expect("FIXTURE: the vault's default facet");
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(member),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = facet;
    vault
        .put_claim(&claim, &body, at(now), now)
        .expect("a record");
    assert_eq!(
        vault
            .get_claim(&claim)
            .expect("claim read")
            .expect("FIXTURE: the CLAIM is stored")
            .scope_facet,
        facet,
        "FIXTURE: the CLAIM sits in the default facet"
    );

    let claim_band = selector_range_of(ENTITY_TYPE_CLAIM).expect("FIXTURE: a CLAIM has a band");
    let other_band = SelectorRange::Family(TypeByteFamily::Conversation);
    assert!(
        !other_band.includes(claim_band),
        "FIXTURE: the other band does not hold a CLAIM"
    );
    let selector = |facets: Vec<EntityId>, bands: Vec<SelectorRange>| {
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, facets, bands);
        authorize_sync_selector(&vault, scope, &selector)
            .expect("FIXTURE: the member's selector is authorized");
        selector
    };
    let open = selector(vec![], vec![]);
    let own_band = selector(vec![], vec![claim_band]);
    let other_band = selector(vec![], vec![other_band]);
    let own_facet = selector(vec![facet], vec![]);
    let other_facet = selector(vec![EntityId::now()], vec![]);

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    assert!(
        packed.get_map("entities").get(&claim.to_hex()).is_some(),
        "FIXTURE: the packed window holds the CLAIM"
    );
    persist_window(&vault, &packed, &key);
    assert!(
        vault
            .delete_entity_with_reason(&claim, DeleteReason::UserHardDelete)
            .expect("FIXTURE: the owner's delete")
            .existed,
        "FIXTURE: the CLAIM existed"
    );
    let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
    assert!(
        window.get_map("tombstones").get(&claim.to_hex()).is_some(),
        "FIXTURE: the window holds the CLAIM's tombstone"
    );
    let carries = |selector: &SyncSelector| {
        filtered_window_doc(&vault, &window, &key, scope, selector)
            .expect("the member's selector window")
            .get_map("tombstones")
            .get(&claim.to_hex())
            .is_some()
    };
    Carried {
        open: carries(&open),
        own_band: carries(&own_band),
        other_band: carries(&other_band),
        own_facet: carries(&own_facet),
        other_facet: carries(&other_facet),
    }
}

#[test]
fn a_band_narrowed_members_window_carries_its_bands_hard_delete() {
    let carried = exports_after_hard_delete();
    assert!(
        carried.open,
        "FIXTURE: the member's open window carries the CLAIM's tombstone"
    );
    assert!(
        carried.own_band,
        "MISSED-DELETE: the member's window narrowed to the CLAIM's band drops its tombstone, so \
         the member keeps a row the owner deleted"
    );
    assert!(
        !carried.other_band,
        "LEAK: the member's window narrowed to another band carries the CLAIM's tombstone"
    );
}

#[test]
fn a_facet_narrowed_members_window_carries_its_facets_hard_delete() {
    let carried = exports_after_hard_delete();
    assert!(
        carried.open,
        "FIXTURE: the member's open window carries the CLAIM's tombstone"
    );
    assert!(
        carried.own_facet,
        "MISSED-DELETE: the member's window narrowed to the CLAIM's facet drops its tombstone, so \
         the member keeps a row the owner deleted"
    );
    assert!(
        !carried.other_facet,
        "LEAK: the member's window narrowed to another facet carries the CLAIM's tombstone"
    );
}
