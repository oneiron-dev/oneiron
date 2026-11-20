//! A selector narrowed to some facets carries the hard delete of a row it
//! selected by the row's `FacetOf` stamp
//! (SELECTOR-FACET-EXPORT-DROPS-BODYLESS-TOMBSTONES).
//!
//! A facet-narrowed selector keeps a row whose `FacetOf` edge names a facet
//! it selects (`sync/selector/scope.rs` `facet_scope_by_source`). A hard
//! delete takes the row's body and every edge of it out of the vault's own
//! window in the same commit (`sync/window/tombstones.rs`), so the export
//! keeps no row of it, and the delete travels only through the tombstone rule
//! for rows it does not keep (`sync/selector/tombstones.rs`). Before this fix
//! that rule carried nothing once the selector named a facet, so a peer whose
//! selector names facets never learned of the delete and kept the deleted
//! row. The band axis of the same rule is
//! `tests/selector_band_tombstone_after_hard_delete.rs`, whose fixture this
//! file follows.
//!
//! A member P holds a live Member federation grant whose Scope admits every
//! record. The owner keeps three CLAIMs about P: one stamped `FacetOf` P's
//! facet F, one whose scope facet is F with no `FacetOf` edge, and one
//! stamped `FacetOf` another FACET G. The owner packs and keeps the window
//! and hard-deletes all three. P's selector narrowed to F then carries the
//! stamped CLAIM's tombstone and neither other one; its selector narrowed to
//! G carries the G-stamped CLAIM's tombstone. The same window copied to
//! another vault's machine carries no tombstone at all: that vault's
//! federation admission refuses every one, so a single tombstone failed the
//! whole answer (REVIEW-10024).
//!
//! Each `FIXTURE:` assertion checks the setup, never the export rule.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_facet_tombstone_after_hard_delete`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use loro::{ExportMode, LoroDoc};
use oneiron::authority::PeerMachine;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    filtered_window_doc_for_peer, put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EdgeKind, EntityId, Vault, VaultConfig,
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

/// Whether one selector export carried each deleted CLAIM's tombstone.
#[derive(Debug, Clone, Copy)]
struct Carried {
    /// The CLAIM stamped `FacetOf` F.
    stamped: bool,
    /// The CLAIM whose scope facet is F, with no `FacetOf` edge.
    unstamped: bool,
    /// The CLAIM stamped `FacetOf` G.
    other_stamped: bool,
}

/// What each of the member's selector exports carried after the deletes.
struct Exports {
    /// No facet, band or world filter.
    open: Carried,
    /// Narrowed to F.
    facet: Carried,
    /// Narrowed to G.
    other_facet: Carried,
    /// No filter, copied to another vault's machine.
    other_vault_open: Carried,
    /// Narrowed to F, copied to another vault's machine.
    other_vault_facet: Carried,
}

/// A CLAIM about `member` in `facet`, kept with the owner's put.
fn put_member_claim(vault: &Vault, member: EntityId, facet: EntityId, now: u64) -> EntityId {
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
    claim
}

/// The facets `id`'s stored `FacetOf` edges name.
fn facet_of_targets(vault: &Vault, id: &EntityId) -> Vec<EntityId> {
    vault
        .edges_out(id)
        .expect("FIXTURE: the CLAIM's edges read")
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::FacetOf)
        .map(|edge| edge.target)
        .collect()
}

/// Gives the member a live Member grant whose Scope admits every record,
/// keeps the three CLAIMs in the vault's window, hard-deletes them, and
/// exports the window that is left through each of the member's selectors.
fn exports_after_hard_delete() -> Exports {
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

    // F is the member's substrate facet, which the PERSON put mints; G is a
    // FACET of its own.
    let facet = oneiron::claim::substrate_facet_id(member).expect("the member's facet id");
    let other_facet = EntityId::now();
    vault
        .put_entity(
            &other_facet,
            ENTITY_TYPE_FACET,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "other facet" })).expect("body"),
        )
        .expect("FIXTURE: the other FACET");

    let stamped = put_member_claim(&vault, member, facet, now);
    vault
        .put_edge(&stamped, EdgeKind::FacetOf, &facet, 1.0)
        .expect("FIXTURE: the stamped CLAIM's FacetOf edge");
    let unstamped = put_member_claim(&vault, member, facet, now);
    let other_stamped = put_member_claim(&vault, member, other_facet, now);
    vault
        .put_edge(&other_stamped, EdgeKind::FacetOf, &other_facet, 1.0)
        .expect("FIXTURE: the other CLAIM's FacetOf edge");
    assert_eq!(
        facet_of_targets(&vault, &stamped),
        vec![facet],
        "FIXTURE: the stamped CLAIM names F alone"
    );
    assert!(
        facet_of_targets(&vault, &unstamped).is_empty(),
        "FIXTURE: the unstamped CLAIM has no FacetOf edge"
    );
    assert_eq!(
        facet_of_targets(&vault, &other_stamped),
        vec![other_facet],
        "FIXTURE: the other CLAIM names G alone"
    );

    let selector = |facets: Vec<EntityId>| {
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, facets, vec![]);
        authorize_sync_selector(&vault, scope, &selector)
            .expect("FIXTURE: the member's selector is authorized");
        selector
    };
    let open = selector(vec![]);
    let facet_selector = selector(vec![facet]);
    let other_facet_selector = selector(vec![other_facet]);

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    for claim in [stamped, unstamped, other_stamped] {
        assert!(
            packed.get_map("entities").get(&claim.to_hex()).is_some(),
            "FIXTURE: the packed window holds each CLAIM"
        );
    }
    // Before the deletes, the selector narrowed to F keeps the stamped CLAIM
    // alone, so a tombstone of either other one would name a row it never
    // sent.
    let kept = filtered_window_doc(&vault, &packed, &key, scope, &facet_selector)
        .expect("the member's live selector window");
    let keeps = |claim: &EntityId| kept.get_map("entities").get(&claim.to_hex()).is_some();
    assert!(
        keeps(&stamped) && !keeps(&unstamped) && !keeps(&other_stamped),
        "FIXTURE: the window narrowed to F keeps the stamped CLAIM alone (stamped {}, unstamped \
         {}, other {})",
        keeps(&stamped),
        keeps(&unstamped),
        keeps(&other_stamped)
    );
    persist_window(&vault, &packed, &key);

    for claim in [stamped, unstamped, other_stamped] {
        assert!(
            vault
                .delete_entity_with_reason(&claim, DeleteReason::UserHardDelete)
                .expect("FIXTURE: the owner's delete")
                .existed,
            "FIXTURE: the CLAIM existed"
        );
    }
    let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
    for claim in [stamped, unstamped, other_stamped] {
        assert!(
            window.get_map("tombstones").get(&claim.to_hex()).is_some(),
            "FIXTURE: the window holds each CLAIM's tombstone"
        );
        assert!(
            window.get_map("entities").get(&claim.to_hex()).is_none(),
            "FIXTURE: the delete took each CLAIM's body out of the window"
        );
    }
    let carried_by = |doc: &LoroDoc| {
        let tombstones = doc.get_map("tombstones");
        let carried = |claim: &EntityId| tombstones.get(&claim.to_hex()).is_some();
        Carried {
            stamped: carried(&stamped),
            unstamped: carried(&unstamped),
            other_stamped: carried(&other_stamped),
        }
    };
    let carries = |selector: &SyncSelector| {
        carried_by(
            &filtered_window_doc(&vault, &window, &key, scope, selector)
                .expect("the member's selector window"),
        )
    };
    let carries_to_other_vault = |selector: &SyncSelector| {
        carried_by(
            &filtered_window_doc_for_peer(
                &vault,
                &window,
                &key,
                scope,
                selector,
                PeerMachine::Unknown,
            )
            .expect("the member's selector window for another vault's machine"),
        )
    };
    Exports {
        open: carries(&open),
        facet: carries(&facet_selector),
        other_facet: carries(&other_facet_selector),
        other_vault_open: carries_to_other_vault(&open),
        other_vault_facet: carries_to_other_vault(&facet_selector),
    }
}

#[test]
fn a_facet_narrowed_members_window_carries_its_stamped_rows_hard_delete() {
    let exports = exports_after_hard_delete();
    assert!(
        exports.open.stamped && exports.open.unstamped && exports.open.other_stamped,
        "FIXTURE: the member's open window carries every CLAIM's tombstone: {:?}",
        exports.open
    );
    assert!(
        exports.facet.stamped,
        "MISSED-DELETE: the member's window narrowed to F drops the tombstone of the CLAIM \
         stamped FacetOf F, so the member keeps a row the owner deleted"
    );
    assert!(
        exports.other_facet.other_stamped,
        "MISSED-DELETE: the member's window narrowed to G drops the tombstone of the CLAIM \
         stamped FacetOf G, so the member keeps a row the owner deleted"
    );
}

#[test]
fn a_facet_narrowed_members_window_carries_no_tombstone_of_a_row_it_never_kept() {
    let exports = exports_after_hard_delete();
    assert!(
        exports.open.unstamped && exports.open.other_stamped,
        "FIXTURE: the member's open window carries both CLAIMs' tombstones: {:?}",
        exports.open
    );
    assert!(
        !exports.facet.unstamped,
        "LEAK: the member's window narrowed to F carries the tombstone of a CLAIM whose scope \
         facet is F but which no FacetOf edge placed in F"
    );
    assert!(
        !exports.facet.other_stamped,
        "LEAK: the member's window narrowed to F carries the tombstone of a CLAIM stamped \
         FacetOf G"
    );
    assert!(
        !exports.other_facet.stamped && !exports.other_facet.unstamped,
        "LEAK: the member's window narrowed to G carries the tombstone of a CLAIM in F: {:?}",
        exports.other_facet
    );
}

#[test]
fn a_window_copied_to_another_vault_carries_no_tombstone() {
    let exports = exports_after_hard_delete();
    assert!(
        exports.open.stamped && exports.facet.stamped,
        "FIXTURE: the member's own open and F windows carry the stamped CLAIM's tombstone: open \
         {:?}, F {:?}",
        exports.open,
        exports.facet
    );
    let none = |carried: Carried| !carried.stamped && !carried.unstamped && !carried.other_stamped;
    assert!(
        none(exports.other_vault_open) && none(exports.other_vault_facet),
        "REFUSED-ANSWER: the window copied to another vault's machine carries a tombstone, which \
         that vault's federation admission refuses with the whole answer: open {:?}, F {:?}",
        exports.other_vault_open,
        exports.other_vault_facet
    );
}
