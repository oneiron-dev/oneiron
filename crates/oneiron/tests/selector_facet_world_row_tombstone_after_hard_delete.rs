//! A hard-deleted FACET or WORLD row sends its delete exactly where its live
//! row went (REVIEW-10042 round 2).
//!
//! A selector judges a live FACET and a live WORLD by the row's own id
//! (`sync/selector/scope.rs` `entity_selector_decision`): a selector narrowed
//! to some facets keeps a FACET it names, and a selector narrowed to base
//! reality or to one world keeps a WORLD only under that world's own
//! selector. A hard delete takes the row's carrier out of the vault's own
//! window, so the delete travels only through the tombstone rule for rows the
//! export does not keep (`sync/selector/tombstones.rs`). That rule judged a
//! FACET by `FacetOf` stamps, which a FACET never has, so the facet's own
//! selector dropped its delete; and it judged a WORLD by its captured scope,
//! base reality, which every such selector selects, so a base-reality or
//! other-world selector named a WORLD it never sent.
//!
//! A member P holds a live Member federation grant whose Scope admits every
//! record. The owner keeps two FACETs, or two WORLDs, packs and keeps the
//! window, and hard-deletes one. Each selector then carries its tombstone
//! exactly when it kept the live row.
//!
//! Each `FIXTURE:` assertion checks the setup, never the export rule.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_facet_world_row_tombstone_after_hard_delete`
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::entity_id::LocalWorldId;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SelectorRange, selector_range_of,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{DeleteReason, EntityId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;
use oneiron_contracts::record_layout::EntityMetadataHeader;

const SHARED_SCOPE: FederationGrantScope = FederationGrantScope::vault(7);

struct MemberVault {
    vault: Vault,
    _dir: tempfile::TempDir,
    member: EntityId,
    grant_id: EntityId,
}

impl MemberVault {
    /// A member whose grant reads every record.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary directory");
        let member = EntityId::now();
        let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
            .expect("FIXTURE: the member vault opens");
        // The delete signs as this install first, so the vault needs the
        // keystore a host installs after each open.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let now = vault.now_recorded_at();
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                at(now),
                now,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" }))
                    .expect("FIXTURE: the member body encodes"),
            )
            .expect("FIXTURE: the member PERSON is stored");
        let grant_id = EntityId::now();
        let mut grant = FederationGrant::new(
            SHARED_SCOPE,
            member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        grant.authority_scope = read_preset();
        put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
            .expect("FIXTURE: the member's federation grant is stored");
        Self {
            vault,
            _dir: dir,
            member,
            grant_id,
        }
    }

    fn put_facet(&self, name: &str) -> EntityId {
        let facet = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(
                &facet,
                ENTITY_TYPE_FACET,
                at(now),
                now,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name }))
                    .expect("FIXTURE: the FACET body encodes"),
            )
            .expect("FIXTURE: the FACET is stored");
        facet
    }

    fn put_world(&self) -> EntityId {
        let world = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(&world, ENTITY_TYPE_WORLD, at(now), now, b"world")
            .expect("FIXTURE: the WORLD is stored");
        world
    }

    fn selector(
        &self,
        world: SyncSelectorWorld,
        facets: Vec<EntityId>,
        bands: Vec<SelectorRange>,
    ) -> SyncSelector {
        let selector = SyncSelector::new(self.grant_id, self.member, world, facets, bands);
        authorize_sync_selector(&self.vault, SHARED_SCOPE, &selector)
            .expect("FIXTURE: the member's selector is authorized");
        selector
    }

    /// Packs and keeps the window that holds `row`'s carrier.
    fn pack(&self, row: &EntityId) -> (WindowKey, LoroDoc) {
        let raw = self
            .vault
            .get_raw(row)
            .expect("FIXTURE: the row reads")
            .expect("FIXTURE: the row exists");
        let header = EntityMetadataHeader::parse(&raw).expect("FIXTURE: the row header decodes");
        let key = WindowKey::from_timestamp(header.learned_at);
        let packed = create_window_doc("selector", &key);
        reverse_rematerialize(&self.vault, &packed, &key).expect("FIXTURE: the window packs");
        assert!(
            packed.get_map("entities").get(&row.to_hex()).is_some(),
            "FIXTURE: the packed window holds the live row"
        );
        persist_window(&self.vault, &packed, &key);
        (key, packed)
    }

    /// Hard-deletes `row` and reloads the vault's window `key`.
    fn hard_delete(&self, row: &EntityId, key: &WindowKey) -> LoroDoc {
        assert!(
            self.vault
                .delete_entity_with_reason(row, DeleteReason::UserHardDelete)
                .expect("FIXTURE: the owner's hard delete succeeds")
                .existed,
            "FIXTURE: the deleted row existed"
        );
        let window =
            load_window_from_state(&self.vault, "local", key).expect("FIXTURE: the window reloads");
        let hex = row.to_hex();
        assert!(
            window.get_map("entities").get(&hex).is_none(),
            "FIXTURE: the delete removed the row's carrier from the window"
        );
        assert!(
            window.get_map("tombstones").get(&hex).is_some(),
            "FIXTURE: the window holds the row's tombstone"
        );
        window
    }

    fn export(&self, window: &LoroDoc, key: &WindowKey, selector: &SyncSelector) -> LoroDoc {
        filtered_window_doc(&self.vault, window, key, SHARED_SCOPE, selector)
            .expect("the member's selector exports the window")
    }
}

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
            &doc.export(ExportMode::Snapshot)
                .expect("FIXTURE: the window snapshot encodes"),
        )
        .expect("FIXTURE: the window snapshot is kept");
    vault
        .sync_state_put(&format!("sv:w:{window}"), &doc.oplog_vv().encode())
        .expect("FIXTURE: the window version is kept");
    vault
        .sync_state_put(&format!("svf:w:{window}"), &[1_u8])
        .expect("FIXTURE: the window version flag is kept");
}

fn local_world(world: EntityId) -> SyncSelectorWorld {
    SyncSelectorWorld::World(
        LocalWorldId::from_entity_id(world).expect("FIXTURE: the WORLD has a local id"),
    )
}

#[test]
fn a_facet_narrowed_window_carries_the_delete_of_the_facet_it_selects() {
    let fixture = MemberVault::new();
    let facet = fixture.put_facet("selected facet");
    let other_facet = fixture.put_facet("other facet");
    let hex = facet.to_hex();
    let own = fixture.selector(SyncSelectorWorld::All, vec![facet], vec![]);
    let other = fixture.selector(SyncSelectorWorld::All, vec![other_facet], vec![]);
    let (key, packed) = fixture.pack(&facet);

    assert!(
        fixture
            .export(&packed, &key, &own)
            .get_map("entities")
            .get(&hex)
            .is_some(),
        "FIXTURE: the window narrowed to F keeps the live FACET F"
    );
    assert!(
        fixture
            .export(&packed, &key, &other)
            .get_map("entities")
            .get(&hex)
            .is_none(),
        "FIXTURE: the window narrowed to G does not keep the live FACET F"
    );

    let deleted = fixture.hard_delete(&facet, &key);
    assert!(
        fixture
            .export(&deleted, &key, &own)
            .get_map("tombstones")
            .get(&hex)
            .is_some(),
        "MISSED-DELETE: the window narrowed to F drops the tombstone of the FACET F it kept, so the \
         member keeps a facet the owner deleted"
    );
    assert!(
        fixture
            .export(&deleted, &key, &other)
            .get_map("tombstones")
            .get(&hex)
            .is_none(),
        "LEAK: the window narrowed to G carries the tombstone of the FACET F it never kept"
    );
}

#[test]
fn a_world_row_carries_its_delete_only_under_its_own_world_selector() {
    let fixture = MemberVault::new();
    let world = fixture.put_world();
    let other_world = fixture.put_world();
    let hex = world.to_hex();
    let world_band = selector_range_of(ENTITY_TYPE_WORLD).expect("FIXTURE: a WORLD row has a band");
    let own = fixture.selector(local_world(world), vec![], vec![]);
    let other = fixture.selector(local_world(other_world), vec![], vec![]);
    let base_world_band = fixture.selector(SyncSelectorWorld::Base, vec![], vec![world_band]);
    let (key, packed) = fixture.pack(&world);

    let live_keeps = |selector: &SyncSelector| {
        fixture
            .export(&packed, &key, selector)
            .get_map("entities")
            .get(&hex)
            .is_some()
    };
    assert!(live_keeps(&own), "FIXTURE: World(X) keeps the live WORLD X");
    assert!(
        !live_keeps(&other),
        "FIXTURE: World(Y) does not keep the live WORLD X"
    );
    assert!(
        !live_keeps(&base_world_band),
        "FIXTURE: base reality narrowed to the WORLD band does not keep the live WORLD X"
    );

    let deleted = fixture.hard_delete(&world, &key);
    let carries = |selector: &SyncSelector| {
        fixture
            .export(&deleted, &key, selector)
            .get_map("tombstones")
            .get(&hex)
            .is_some()
    };
    assert!(
        carries(&own),
        "MISSED-DELETE: World(X) drops the tombstone of the WORLD X it kept"
    );
    assert!(
        !carries(&other),
        "LEAK: World(Y) carries the tombstone of the WORLD X it never kept"
    );
    assert!(
        !carries(&base_world_band),
        "LEAK: base reality narrowed to the WORLD band carries the id, reason and time of the \
         WORLD X it never kept"
    );
}
