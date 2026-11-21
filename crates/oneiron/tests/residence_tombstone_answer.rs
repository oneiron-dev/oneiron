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
//! gives no ids, and the same window kept on it gives its ids. A world
//! window's tombstone the home never placed in that window gives no id, an
//! erase alias outranks a plain hard delete, and a selector narrowed to one
//! world answers that world's hard deletes (blind review 2 of #9592/#9593).
//!
//! Each `FIXTURE:` assertion checks the setup, never the answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test residence_tombstone_answer`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::deletion::{TombstoneReason, decode_tombstone_value};
use oneiron::edge::EdgeActorClass;
use oneiron::entity_id::LocalWorldId;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_WORLD};
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
    record_in(vault, subject, relationship, None, now)
}

/// [`record`], scoped to `world` when one is named.
fn record_in(
    vault: &Vault,
    subject: EntityId,
    relationship: Option<EntityId>,
    world: Option<EntityId>,
    now: u64,
) -> EntityId {
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
    body.world = world;
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
    // The window address a delete of the row in this window keeps, as the
    // home's own delete or replay writes it: the residence the answer
    // judges by.
    purged
        .vault
        .sync_state_put(&format!("m:dw:{open}"), key.as_str().as_bytes())
        .expect("FIXTURE: the delete's window address");
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

/// A hard delete is never answered as a soft one. Where the window keeps a
/// soft value under the row's canonical key and a hard one under a
/// case-shifted alias, the answer carries the hard value, as the window's
/// replay holds any hard alias dominant (blind review 1 of #9592). Before,
/// the canonical key's soft value was answered, and the device kept a shell
/// of a row the home had purged.
#[test]
fn a_hard_alias_outranks_a_soft_canonical_value() {
    let purged = Purged::new(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let open = purged.open_claim.to_hex();
    let hard = window_bytes(&purged.window, "tombstones", &open);
    assert_eq!(
        hard.first(),
        Some(&(TombstoneReason::UserHardDelete as u8)),
        "FIXTURE: the owner's delete is hard"
    );
    let mut soft = hard.clone();
    soft[0] = TombstoneReason::UserDelete as u8;
    assert!(
        !decode_tombstone_value(&soft).is_hard(),
        "FIXTURE: the canonical key's value is soft"
    );
    let window = create_window_doc("selector", &purged.key);
    let tombstones = window.get_map("tombstones");
    tombstones
        .insert(&open, soft.as_slice())
        .expect("FIXTURE: the window holds the soft value under the canonical key");
    tombstones
        .insert(&open.to_uppercase(), hard.as_slice())
        .expect("FIXTURE: the window holds the hard value under the alias");
    window.commit();
    let answer = window_tombstone_projection_with(
        &purged.vault,
        &window,
        &purged.key,
        purged.scope,
        &purged.selector,
        Withhold::Unknown,
    )
    .expect("the tombstone answer");
    let entry = answer
        .iter()
        .find(|entry| entry.entity_id == purged.open_claim)
        .unwrap_or_else(|| panic!("the answer names the open CLAIM: {answer:?}"));
    assert_eq!(
        entry.value, hard,
        "DOWNGRADE: the answer carries the soft value of a row a hard alias deleted"
    );
}

/// A world window's tombstone the home never placed in that window gives no
/// id (blind review 2 of #9593). A world window's ingress keeps a tombstone
/// of an id it cannot place, and the window's replay never applies it here,
/// so the home does not vouch for it: a device that holds the row elsewhere
/// would purge it. Only once the home's own window address for the delete
/// names this window does the id leave. Before, the answer named every
/// tombstone the window map held.
#[test]
fn a_world_tombstone_the_home_never_placed_gives_no_id() {
    let purged = Purged::new(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let at = purged.key.start_timestamp().expect("the window's month");
    let key = WindowKey::for_world(at, EntityId::now());
    let window = create_window_doc("selector", &key);
    let open = purged.open_claim.to_hex();
    let value = window_bytes(&purged.window, "tombstones", &open);
    window
        .get_map("tombstones")
        .insert(&open, value.as_slice())
        .expect("FIXTURE: the world window holds the tombstone");
    window.commit();
    let readable = BTreeSet::new();
    assert_eq!(
        purged.answered(&window, &key, Withhold::Worlds(&readable)),
        Vec::<EntityId>::new(),
        "FORGED DELETE: the home vouches for a world tombstone it never placed in the window"
    );
    let elsewhere = WindowKey::for_world(at, EntityId::now());
    purged
        .vault
        .sync_state_put(&format!("m:dw:{open}"), elsewhere.as_str().as_bytes())
        .expect("FIXTURE: the delete's window address names another window");
    assert_eq!(
        purged.answered(&window, &key, Withhold::Worlds(&readable)),
        Vec::<EntityId>::new(),
        "FORGED DELETE: a delete the home placed in another window leaves from this one"
    );
    purged
        .vault
        .sync_state_put(&format!("m:dw:{open}"), key.as_str().as_bytes())
        .expect("FIXTURE: the delete's window address names this window");
    assert_eq!(
        purged.answered(&window, &key, Withhold::Worlds(&readable)),
        vec![purged.open_claim],
        "OVER-REFUSAL: a delete the home placed in this window leaves"
    );
}

/// Among hard values, an erase outranks a plain hard delete (blind review 2
/// of #9592). Where the window keeps a plain hard delete under the row's
/// canonical key and an owner erase under a case-shifted alias, the answer
/// carries the erase, whose replay erases the row's checkpoint payloads.
/// Before, the canonical key's plain delete was answered, and a device that
/// held the row kept its payloads.
#[test]
fn an_erase_alias_outranks_a_plain_hard_canonical_value() {
    let purged = Purged::new(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let open = purged.open_claim.to_hex();
    let hard = window_bytes(&purged.window, "tombstones", &open);
    assert_eq!(
        hard.first(),
        Some(&(TombstoneReason::UserHardDelete as u8)),
        "FIXTURE: the owner's delete is a plain hard delete"
    );
    let mut erase = hard.clone();
    erase[0] = TombstoneReason::OwnerErase as u8;
    assert!(
        decode_tombstone_value(&erase).is_hard(),
        "FIXTURE: the alias's erase is hard"
    );
    let window = create_window_doc("selector", &purged.key);
    let tombstones = window.get_map("tombstones");
    tombstones
        .insert(&open, hard.as_slice())
        .expect("FIXTURE: the window holds the plain delete under the canonical key");
    tombstones
        .insert(&open.to_uppercase(), erase.as_slice())
        .expect("FIXTURE: the window holds the erase under the alias");
    window.commit();
    let answer = window_tombstone_projection_with(
        &purged.vault,
        &window,
        &purged.key,
        purged.scope,
        &purged.selector,
        Withhold::Unknown,
    )
    .expect("the tombstone answer");
    let entry = answer
        .iter()
        .find(|entry| entry.entity_id == purged.open_claim)
        .unwrap_or_else(|| panic!("the answer names the open CLAIM: {answer:?}"));
    assert_eq!(
        entry.value, erase,
        "ERASE LOST: the answer carries a plain hard delete of a row an alias erased"
    );
}

/// A selector narrowed to one world answers that world's hard deletes (blind
/// review 2 of #9592/#9593). A member follows world W under an authorized
/// `World(W)` selector; the owner hard-deletes a CLAIM of W the member
/// reads. Its carrier left the window with the delete, so the selector keeps
/// no row of it, and the delete's captured position in W is what lets its
/// tombstone travel. Before, a selector other than All carried no tombstone
/// of a row it did not keep, and the device never learned of the delete.
#[test]
fn a_world_selector_answers_its_worlds_hard_deletes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let now = vault.now_recorded_at();
    let world = EntityId::now();
    vault
        .put_entity(&world, ENTITY_TYPE_WORLD, at(now), now, b"world")
        .expect("a world");
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
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(LocalWorldId::from_entity_id(world).expect("a local world")),
        vec![],
        vec![],
    );
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's world selector is authorized");

    let claim = record_in(&vault, member, None, Some(world), now);
    let key = WindowKey::for_world(now, world);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    persist_window(&vault, &packed, &key);
    assert!(
        vault
            .delete_entity_with_reason(&claim, DeleteReason::UserHardDelete)
            .expect("FIXTURE: the owner's delete")
            .existed,
        "FIXTURE: the world's CLAIM existed"
    );
    let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
    assert!(
        window.get_map("tombstones").get(&claim.to_hex()).is_some(),
        "FIXTURE: the world's window holds the CLAIM's tombstone"
    );
    let ids: Vec<EntityId> = window_tombstone_projection_with(
        &vault,
        &window,
        &key,
        scope,
        &selector,
        Withhold::Worlds(&BTreeSet::new()),
    )
    .expect("the tombstone answer")
    .into_iter()
    .map(|entry| entry.entity_id)
    .collect();
    assert_eq!(
        ids,
        vec![claim],
        "MISSED DELETE: a world selector's answer omits its world's hard delete"
    );
}
