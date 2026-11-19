//! A followed window's tombstone id set names only the rows its device reads
//! (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; Engine ANSWER
//! FOLLOWED-WORLD-TOMBSTONE-IDS-FIX-OR-PARK = A, Thu 19 Nov 12:44: "the
//! tombstone answer names only ids the requesting device could read (the
//! same reader check the window uses, row by row) ... A withheld world gives
//! no ids").
//!
//! The home answers `residence.tombstones` from
//! `window_tombstone_projection_with`, the tombstones map of the selector
//! export a granted window sync sends. The fixture is the one of
//! `tests/selector_tombstone_label.rs`: a member P holds a live Member
//! federation grant whose Scope admits every record, but no grant on a
//! relationship R and no membership in it. The owner hard-deletes an open
//! CLAIM and a CLAIM keyed to R. P's answer names the open CLAIM and never the
//! R CLAIM; a co-Owner's names both. A world window kept off the machine
//! gives no ids, and the same window kept on it gives its ids.
//!
//! Each `FIXTURE:` assertion checks the setup, never the answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test residence_tombstone_answer`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::sync::residence::window_tombstone_projection_with;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{Withhold, load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::write_envelope::claim_body::relationship_scope_of;
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

/// A stated CLAIM about `subject` learned at `now`, keyed to `relationship`
/// when one is named.
fn record(vault: &Vault, subject: EntityId, relationship: Option<EntityId>, now: u64) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.rel = relationship_scope_of(relationship);
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
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

/// The bytes the window map `name` of `doc` holds under `key`.
fn window_bytes(doc: &LoroDoc, name: &str, key: &str) -> Vec<u8> {
    match doc.get_map(name).get(key) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
        _ => panic!("FIXTURE: the window's {name} map holds bytes under {key}"),
    }
}

/// A member vault whose window holds the tombstones of an open CLAIM and of a
/// CLAIM keyed to R, both hard-deleted by the owner, and the member's
/// authorized selector under a grant of `role`.
struct Purged {
    _dir: tempfile::TempDir,
    vault: Vault,
    scope: FederationGrantScope,
    selector: SyncSelector,
    key: WindowKey,
    window: LoroDoc,
    open_claim: EntityId,
    purged_claim: EntityId,
}

impl Purged {
    fn new(role: FederationGrantRole, preset: FederationGrantPreset) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let member = EntityId::now();
        let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
            .expect("fixture vault");
        // Every delete signs as this install first, so the vault needs the
        // keystore a host installs after each open.
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let now = vault.now_recorded_at();
        let relationship = EntityId::now();
        vault
            .put_entity(
                &relationship,
                ENTITY_TYPE_RELATIONSHIP,
                at(now),
                now,
                b"relationship",
            )
            .expect("a relationship");
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                at(now),
                now,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
            )
            .expect("a member outside the relationship");

        let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
        let grant_id = EntityId::now();
        let mut grant = FederationGrant::new(scope, member, role, preset);
        grant.authority_scope = read_preset();
        put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
            .expect("the member's federation grant");
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        authorize_sync_selector(&vault, scope, &selector)
            .expect("FIXTURE: the member's selector is authorized");

        let open_claim = record(&vault, member, None, now);
        let purged_claim = record(&vault, member, Some(relationship), now);
        if matches!(role, FederationGrantRole::Member) {
            let reads = |id: EntityId| {
                vault
                    .memory(member, EdgeActorClass::Human)
                    .get_entity(&id.to_hex())
                    .expect("member read")
                    .value
                    .is_some()
            };
            assert!(
                reads(open_claim),
                "FIXTURE: the member reads the open CLAIM"
            );
            assert!(
                !reads(purged_claim),
                "FIXTURE: the member does not read the R CLAIM"
            );
        }

        let key = WindowKey::from_timestamp(now);
        let packed = create_window_doc("selector", &key);
        reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
        persist_window(&vault, &packed, &key);
        for id in [open_claim, purged_claim] {
            assert!(
                vault
                    .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
                    .expect("FIXTURE: the owner's delete")
                    .existed,
                "FIXTURE: the purged CLAIM existed"
            );
        }
        let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
        for id in [open_claim, purged_claim] {
            assert!(
                window.get_map("tombstones").get(&id.to_hex()).is_some(),
                "FIXTURE: the vault's window holds the tombstone of {}",
                id.to_hex()
            );
        }
        Self {
            _dir: dir,
            vault,
            scope,
            selector,
            key,
            window,
            open_claim,
            purged_claim,
        }
    }

    /// The ids the answer for `window` under `key` names, to a machine
    /// `withhold` describes.
    fn answered(&self, window: &LoroDoc, key: &WindowKey, withhold: Withhold<'_>) -> Vec<EntityId> {
        window_tombstone_projection_with(
            &self.vault,
            window,
            key,
            self.scope,
            &self.selector,
            withhold,
        )
        .expect("the tombstone answer")
        .into_iter()
        .map(|entry| entry.entity_id)
        .collect()
    }
}

#[test]
fn the_tombstone_answer_names_only_rows_its_member_reads() {
    let purged = Purged::new(FederationGrantRole::Member, FederationGrantPreset::Member);
    let ids = purged.answered(&purged.window, &purged.key, Withhold::Unknown);
    assert!(
        ids.contains(&purged.open_claim),
        "the answer names the open CLAIM the member read: {ids:?}"
    );
    assert!(
        !ids.contains(&purged.purged_claim),
        "LEAK: the answer names the R CLAIM to a member who does not read R: {ids:?}"
    );
}

#[test]
fn a_co_owners_tombstone_answer_names_every_deleted_row() {
    let purged = Purged::new(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let ids = purged.answered(&purged.window, &purged.key, Withhold::Unknown);
    assert!(
        ids.contains(&purged.open_claim) && ids.contains(&purged.purged_claim),
        "OVER-REFUSAL: a co-Owner's answer names every deleted row: {ids:?}"
    );
}

#[test]
fn a_withheld_world_window_answers_no_ids() {
    let purged = Purged::new(FederationGrantRole::Member, FederationGrantPreset::Member);
    // A world window holding the open CLAIM's tombstone, its value as the
    // owner's delete wrote it.
    let world = EntityId::now();
    let at = purged.key.start_timestamp().expect("the window's month");
    let key = WindowKey::for_world(at, world);
    let window = create_window_doc("selector", &key);
    let open = purged.open_claim.to_hex();
    let value = window_bytes(&purged.window, "tombstones", &open);
    window
        .get_map("tombstones")
        .insert(&open, value.as_slice())
        .expect("FIXTURE: the world window holds the tombstone");
    window.commit();
    assert_eq!(
        purged.answered(&window, &key, Withhold::Worlds(&BTreeSet::new())),
        vec![purged.open_claim],
        "FIXTURE: a machine that may read the world gets its window's ids"
    );
    let kept_off = BTreeSet::from([world]);
    assert_eq!(
        purged.answered(&window, &key, Withhold::Worlds(&kept_off)),
        Vec::<EntityId>::new(),
        "a world kept off the machine gives no ids"
    );
}
