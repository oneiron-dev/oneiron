//! SELECTOR-TOMBSTONE-REVIEW-10024-PROOFS (REVIEW-10024 P1-1/P1-4,
//! REVIEW-10042 P1).
//!
//! A hard-deleted NOTE stays off a destination that could not receive its
//! world's words. It still sends its delete under a world selector that kept
//! the live NOTE, even when the NOTE was also in another world, and to a
//! grant that reads only that world when the NOTE was also in base reality.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_note_tombstone_after_hard_delete`
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::claim::base_world_id;
use oneiron::deletion::{TombstoneReason, decode_tombstone_value};
use oneiron::entity_id::LocalWorldId;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope, Scope,
    ScopeId,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{Withhold, load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc_for,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{DeleteReason, EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
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
    fn new() -> Self {
        Self::reading(read_preset())
    }

    /// A member whose grant reads the records of `worlds` alone.
    fn reading_only(worlds: &[EntityId]) -> Self {
        let mut authority_scope = read_preset();
        authority_scope.worlds = worlds.iter().map(|world| ScopeId(*world)).collect();
        Self::reading(authority_scope)
    }

    fn reading(authority_scope: Scope) -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary directory");
        let member = EntityId::now();
        let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
            .expect("FIXTURE: the member vault opens");
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
        grant.authority_scope = authority_scope;
        put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
            .expect("FIXTURE: the member's federation grant is stored");
        Self {
            vault,
            _dir: dir,
            member,
            grant_id,
        }
    }

    fn put_world(&self) -> EntityId {
        let world = EntityId::now();
        self.store_world(world);
        world
    }

    fn store_world(&self, world: EntityId) {
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(&world, ENTITY_TYPE_WORLD, at(now), now, b"world")
            .expect("FIXTURE: the WORLD is stored");
    }

    fn put_note(&self, worlds: &[EntityId]) -> EntityId {
        let (owner, _) = embedded_owner(&self.vault).expect("FIXTURE: the embedded owner is bound");
        let receipt = self
            .vault
            .memory(owner, EdgeActorClass::Human)
            .create_note("research", "Field notes from the harbor.")
            .expect("FIXTURE: the owner writes a NOTE");
        let note = EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the NOTE has an id");
        for world in worlds {
            self.vault
                .put_edge(&note, EdgeKind::InWorld, world, 1.0)
                .expect("FIXTURE: the NOTE joins the world");
        }
        assert_eq!(
            self.note_worlds(&note),
            worlds.iter().copied().collect::<BTreeSet<_>>(),
            "FIXTURE: the NOTE has exactly the requested InWorld targets"
        );
        note
    }

    fn note_worlds(&self, note: &EntityId) -> BTreeSet<EntityId> {
        self.vault
            .edges_out(note)
            .expect("FIXTURE: the NOTE's outbound edges read")
            .into_iter()
            .filter(|edge| edge.kind == EdgeKind::InWorld)
            .map(|edge| edge.target)
            .collect()
    }

    fn selector(&self, world: SyncSelectorWorld) -> SyncSelector {
        let selector = SyncSelector::new(self.grant_id, self.member, world, vec![], vec![]);
        authorize_sync_selector(&self.vault, SHARED_SCOPE, &selector)
            .expect("FIXTURE: the member's selector is authorized");
        selector
    }

    fn pack(&self, note: &EntityId) -> (WindowKey, LoroDoc) {
        let raw = self
            .vault
            .get_raw(note)
            .expect("FIXTURE: the NOTE row reads")
            .expect("FIXTURE: the NOTE row exists");
        let header = EntityMetadataHeader::parse(&raw).expect("FIXTURE: the NOTE header decodes");
        // InWorld controls NOTE selection, not the NOTE carrier's window address.
        let key = WindowKey::from_timestamp(header.learned_at);
        let packed = create_window_doc("selector", &key);
        reverse_rematerialize(&self.vault, &packed, &key).expect("FIXTURE: the window packs");
        assert!(
            packed.get_map("entities").get(&note.to_hex()).is_some(),
            "FIXTURE: the base month window holds the live NOTE"
        );
        persist_window(&self.vault, &packed, &key);
        (key, packed)
    }

    fn hard_delete(&self, note: &EntityId, key: &WindowKey) -> LoroDoc {
        assert!(
            self.vault
                .delete_entity_with_reason(note, DeleteReason::UserHardDelete)
                .expect("FIXTURE: the hard delete succeeds")
                .existed,
            "FIXTURE: the deleted NOTE existed"
        );
        assert!(
            self.note_worlds(note).is_empty(),
            "FIXTURE: the delete removed the NOTE's InWorld edges"
        );
        let window =
            load_window_from_state(&self.vault, "local", key).expect("FIXTURE: the window reloads");
        let hex = note.to_hex();
        assert!(
            window.get_map("entities").get(&hex).is_none(),
            "FIXTURE: the delete removed the NOTE's carrier from the window"
        );
        let Some(ValueOrContainer::Value(LoroValue::Binary(value))) =
            window.get_map("tombstones").get(&hex)
        else {
            panic!("FIXTURE: the window holds the NOTE's tombstone bytes");
        };
        assert_eq!(
            decode_tombstone_value(&value).reason,
            Some(TombstoneReason::UserHardDelete),
            "FIXTURE: the window holds the user's hard delete"
        );
        window
    }

    fn export(
        &self,
        window: &LoroDoc,
        key: &WindowKey,
        selector: &SyncSelector,
        withheld: &BTreeSet<EntityId>,
    ) -> LoroDoc {
        filtered_window_doc_for(
            &self.vault,
            window,
            key,
            SHARED_SCOPE,
            selector,
            Withhold::Worlds(withheld),
        )
        .expect("the member's selector exports the window")
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

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

#[test]
fn a_device_only_worlds_note_keeps_its_tombstone_home() {
    let fixture = MemberVault::new();
    let w = fixture.put_world();
    let note = fixture.put_note(&[w]);
    let hex = note.to_hex();
    let selector = fixture.selector(SyncSelectorWorld::All);
    let (key, packed) = fixture.pack(&note);
    let withhold_w = BTreeSet::from([w]);
    let withhold_none = BTreeSet::new();
    let export = |window: &LoroDoc, withheld: &BTreeSet<EntityId>| {
        fixture.export(window, &key, &selector, withheld)
    };

    let portable = export(&packed, &withhold_none);
    let device_only = export(&packed, &withhold_w);
    assert!(
        portable.get_map("entities").get(&hex).is_some(),
        "FIXTURE: the live NOTE travels when no world is withheld"
    );
    assert!(
        device_only.get_map("entities").get(&hex).is_none(),
        "FIXTURE: the live NOTE stays home when W is withheld"
    );

    let deleted = fixture.hard_delete(&note, &key);
    let portable = export(&deleted, &withhold_none);
    assert!(
        portable.get_map("tombstones").get(&hex).is_some(),
        "FIXTURE: the NOTE's tombstone travels when no world is withheld"
    );
    let device_only = export(&deleted, &withhold_w);
    assert!(
        device_only.get_map("tombstones").get(&hex).is_none(),
        "LEFT DEVICE: the NOTE's tombstone traveled to a destination that withholds W"
    );
}

#[test]
fn a_note_in_two_worlds_carries_its_delete_under_either_world_selector() {
    let fixture = MemberVault::new();
    let w = fixture.put_world();
    let x = fixture.put_world();
    let y = fixture.put_world();
    let note = fixture.put_note(&[w, x]);
    let hex = note.to_hex();
    let world_selector = |world| {
        fixture.selector(SyncSelectorWorld::World(
            LocalWorldId::from_entity_id(world).expect("FIXTURE: the WORLD has a local id"),
        ))
    };
    let selector_w = world_selector(w);
    let selector_y = world_selector(y);
    let (key, packed) = fixture.pack(&note);
    let withhold_none = BTreeSet::new();
    let export = |window: &LoroDoc, selector: &SyncSelector| {
        fixture.export(window, &key, selector, &withhold_none)
    };

    let live_w = export(&packed, &selector_w);
    let live_y = export(&packed, &selector_y);
    assert!(
        live_w.get_map("entities").get(&hex).is_some(),
        "FIXTURE: World(W) keeps the live NOTE in W and X"
    );
    assert!(
        live_y.get_map("entities").get(&hex).is_none(),
        "FIXTURE: World(Y) does not keep the live NOTE in W and X"
    );

    let deleted = fixture.hard_delete(&note, &key);
    let deleted_w = export(&deleted, &selector_w);
    let deleted_y = export(&deleted, &selector_y);
    assert!(
        deleted_w.get_map("tombstones").get(&hex).is_some(),
        "MISSED-DELETE: World(W) dropped the tombstone of the NOTE it kept in W and X"
    );
    assert!(
        deleted_y.get_map("tombstones").get(&hex).is_none(),
        "LEAK: World(Y) carried the tombstone of a NOTE it never kept"
    );
}

#[test]
fn a_note_in_base_and_a_world_carries_its_delete_to_a_grant_reading_only_that_world() {
    let w = EntityId::now();
    let x = EntityId::now();
    let base = base_world_id();
    let fixture = MemberVault::reading_only(&[w]);
    fixture.store_world(w);
    fixture.store_world(x);
    let kept = fixture.put_note(&[base, w]);
    let unkept = fixture.put_note(&[base, x]);
    let (kept_hex, unkept_hex) = (kept.to_hex(), unkept.to_hex());
    let selector = fixture.selector(SyncSelectorWorld::World(
        LocalWorldId::from_entity_id(w).expect("FIXTURE: the WORLD has a local id"),
    ));
    let (key, packed) = fixture.pack(&kept);
    assert!(
        packed.get_map("entities").get(&unkept_hex).is_some(),
        "FIXTURE: the base month window also holds the live NOTE in base and X"
    );
    let withhold_none = BTreeSet::new();
    let export = |window: &LoroDoc| fixture.export(window, &key, &selector, &withhold_none);

    let live = export(&packed);
    assert!(
        live.get_map("entities").get(&kept_hex).is_some(),
        "FIXTURE: the grant reading only W keeps the live NOTE in base and W"
    );
    assert!(
        live.get_map("entities").get(&unkept_hex).is_none(),
        "FIXTURE: the grant reading only W does not keep the live NOTE in base and X"
    );

    fixture.hard_delete(&kept, &key);
    let deleted = export(&fixture.hard_delete(&unkept, &key));
    assert!(
        deleted.get_map("tombstones").get(&kept_hex).is_some(),
        "MISSED-DELETE: the grant reading only W dropped the tombstone of the NOTE in base and W it kept"
    );
    assert!(
        deleted.get_map("tombstones").get(&unkept_hex).is_none(),
        "LEAK: the grant reading only W carried the tombstone of a NOTE in base and X it never kept"
    );
}
