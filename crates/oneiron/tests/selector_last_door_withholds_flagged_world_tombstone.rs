//! CROSS-VAULT-DELETE-SELECTOR-ANSWER-RELEASE, PR 2 (emissionreview R3).
//!
//! A selector answer is filtered under the world flags read when it is built,
//! then waits in its queue for its last door
//! (`sync::window::selector_update_verdict_for_peer`). A hard-deleted NOTE's
//! tombstone carries no words, but the capture bound to its delete says the
//! NOTE carried the words of world W. When the owner keeps W on this machine
//! while the answer waits, the last door withholds the answer that carries
//! the NOTE's delete, as the filter would have withheld the tombstone itself;
//! a flag on another world leaves it portable.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_last_door_withholds_flagged_world_tombstone`
// `put_selector_test_federation_grant` exists only under `test-hooks`, and
// `keep_world_on_this_machine_for_test` only under `test-support`.
#![cfg(all(oneiron_test_support, feature = "test-hooks", feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::PeerMachine;
use oneiron::deletion::{TombstoneReason, decode_tombstone_value};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{
    UpdateVerdict, Withhold, load_window_from_state, reverse_rematerialize,
    selector_update_verdict_for_peer,
};
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

    fn put_world(&self) -> EntityId {
        let world = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(&world, ENTITY_TYPE_WORLD, at(now), now, b"world")
            .expect("FIXTURE: the WORLD is stored");
        world
    }

    fn put_note(&self, world: EntityId) -> EntityId {
        let (owner, _) = embedded_owner(&self.vault).expect("FIXTURE: the embedded owner is bound");
        let receipt = self
            .vault
            .memory(owner, EdgeActorClass::Human)
            .create_note("research", "Field notes from the harbor.")
            .expect("FIXTURE: the owner writes a NOTE");
        let note = EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the NOTE has an id");
        self.vault
            .put_edge(&note, EdgeKind::InWorld, &world, 1.0)
            .expect("FIXTURE: the NOTE joins the world");
        assert_eq!(
            self.note_worlds(&note),
            BTreeSet::from([world]),
            "FIXTURE: the NOTE is in W alone"
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

    fn selector(&self) -> SyncSelector {
        let selector = SyncSelector::new(
            self.grant_id,
            self.member,
            SyncSelectorWorld::All,
            vec![],
            vec![],
        );
        authorize_sync_selector(&self.vault, SHARED_SCOPE, &selector)
            .expect("FIXTURE: the member's selector is authorized");
        selector
    }

    /// Packs the base month window that holds the live NOTE and keeps it.
    fn pack(&self, note: &EntityId) -> WindowKey {
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
        key
    }

    /// Hard-deletes the NOTE; the window it sat in, holding its tombstone.
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
        assert!(
            window.get_map("entities").get(&note.to_hex()).is_none(),
            "FIXTURE: the delete removed the NOTE's carrier from the window"
        );
        window
    }

    /// The answer the member's selector takes of `window` while no world is
    /// withheld from the machine it serves: the delete of the NOTE travels.
    /// Its last door judges an update that carries that delete alone, the
    /// answer of a window whose other rows the selector does not take.
    fn queued_delete(&self, window: &LoroDoc, key: &WindowKey, note: &EntityId) -> Vec<u8> {
        let nothing_withheld = BTreeSet::new();
        let answer = filtered_window_doc_for(
            &self.vault,
            window,
            key,
            SHARED_SCOPE,
            &self.selector(),
            Withhold::Worlds(&nothing_withheld),
        )
        .expect("FIXTURE: the member's selector exports the window");
        let hex = note.to_hex();
        let Some(ValueOrContainer::Value(LoroValue::Binary(value))) =
            answer.get_map("tombstones").get(&hex)
        else {
            panic!("FIXTURE: the answer carries the NOTE's tombstone while W is portable");
        };
        assert_eq!(
            decode_tombstone_value(&value).reason,
            Some(TombstoneReason::UserHardDelete),
            "FIXTURE: the answer carries the user's hard delete"
        );
        let delete_alone = create_window_doc("selector", key);
        delete_alone
            .get_map("tombstones")
            .insert(&hex, LoroValue::Binary(value))
            .expect("FIXTURE: the delete is copied into the queued answer");
        delete_alone.commit();
        delete_alone
            .export(ExportMode::all_updates())
            .expect("FIXTURE: the queued answer encodes")
    }

    /// The last door's verdict on the queued answer, toward a machine other
    /// than this one.
    fn last_door(&self, key: &WindowKey, update: &[u8]) -> UpdateVerdict {
        selector_update_verdict_for_peer(&self.vault, key.as_str(), update, PeerMachine::Unknown)
    }

    fn keep_on_this_machine(&self, world: EntityId) {
        self.vault
            .keep_world_on_this_machine_for_test(world, true)
            .expect("FIXTURE: the owner keeps the world on this machine");
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
fn a_world_kept_home_while_the_answer_waits_withholds_its_delete_at_the_last_door() {
    let fixture = MemberVault::new();
    let w = fixture.put_world();
    let note = fixture.put_note(w);
    let key = fixture.pack(&note);
    let deleted = fixture.hard_delete(&note, &key);
    let queued = fixture.queued_delete(&deleted, &key, &note);
    assert_eq!(
        fixture.last_door(&key, &queued),
        UpdateVerdict::Portable,
        "FIXTURE: the answer leaves while W is portable"
    );

    fixture.keep_on_this_machine(w);
    assert_eq!(
        fixture.last_door(&key, &queued),
        UpdateVerdict::Withheld,
        "LEFT DEVICE: the last door sent the delete of a NOTE in W after the owner kept W on this machine"
    );
}

#[test]
fn a_flag_on_another_world_leaves_the_queued_delete_portable() {
    let fixture = MemberVault::new();
    let w = fixture.put_world();
    let x = fixture.put_world();
    let note = fixture.put_note(w);
    let key = fixture.pack(&note);
    let deleted = fixture.hard_delete(&note, &key);
    let queued = fixture.queued_delete(&deleted, &key, &note);

    fixture.keep_on_this_machine(x);
    assert_eq!(
        fixture.last_door(&key, &queued),
        UpdateVerdict::Portable,
        "the last door withheld the delete of a NOTE in W when only X is kept on this machine"
    );
}
