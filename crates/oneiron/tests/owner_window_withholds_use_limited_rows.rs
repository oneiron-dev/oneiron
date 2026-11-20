//! A row a refused privacy erase keeps for storage only leaves the owner's full window and the
//! owner's text lane (Engine ANSWER SERVING-DOORS-OWNER-WINDOW-USE-LIMIT = B, 20 Nov 21:19; FIX
//! USE-LIMIT-NOT-ASKED-BY-SERVING-DOORS (e)/(f)).
//!
//! The ruling: "a C6 row packs as withheld in the owner window (like a device-only row) and
//! export_owner refuses it, so devices drop it the way they drop an erased row." The hosted vault
//! keeps its stored copy for the hold.
//!
//! * `a_kept_row_leaves_the_owner_window_and_the_device_holds_it_back`: a hosted hub and an own
//!   device share a window that carries two rows. A customer hold refuses the privacy erase of
//!   one. The hub's next export takes its carrier out of the window and files a withholding
//!   marker; the device lands both, so its window no longer carries the row (a restore from the
//!   device's window lacks it), the row reads to no one there, and the device's own packing never
//!   sends it back (an edit the device makes to it stays local). The other row rides as before.
//! * `a_peer_behind_the_kept_row_takes_a_replacement_without_it`: after the keep, the hub answers a
//!   peer that holds nothing of the window with a replacement snapshot, and a fresh device synced
//!   through the doors holds the other row and no byte of the kept one.
//! * `the_owner_lane_sends_no_text_of_a_kept_note`: a hosted vault's owner-lane export of a NOTE
//!   answers before the keep and refuses after it, and a frame queued before the keep is withheld
//!   at release.
//! * `a_send_queued_before_the_keep_is_withheld_at_release` (REVIEW-9846 P1 1): window bytes that
//!   insert the row's carrier, queued before the keep and released after it, are withheld at the
//!   door that sends them; the hub's scrubbed export, which carries the withholding marker,
//!   still sends.
//! * `an_edge_naming_a_kept_row_carried_elsewhere_leaves_the_window` (REVIEW-9846 P1 5, round 2
//!   P1 2): a window carries an edge to the kept row, whose own carrier rides in another month's
//!   window. The hub's next export of it takes the edge out and files no marker there, since a
//!   marker in a window that never carries the row would hold it back again after the limit
//!   lifts; the row's own window loses its carrier and carries the marker.
//! * `an_already_synced_device_installs_a_replacement_without_the_kept_row` (round 2 P1 1): a
//!   device that still stores the kept row installs the hub's replacement, which names the row by
//!   its marker alone; the installed window does not carry the row back from the device's store.
//! * `a_device_holding_a_kept_note_back_never_packs_it_again` (round 2 P1 4): a device that landed
//!   the marker for a kept NOTE still stores the NOTE and holds no use limit; its own NOTE refresh
//!   never packs the NOTE into its window again.
//! * `a_kept_notes_pending_fork_text_leaves_the_window` (REVIEW-9846 P1 3): before the keep, the
//!   window packs a NOTE's undecided fork text; after it, the export carries no byte of that text
//!   and no carrier of the NOTE, and files the marker.
//!
//! Named limits, not tested here: a whole-vault export run on the device still carries the held
//! row's bytes (its egress asks off-record and the device's own use limits, not the source
//! audience hold); the hosted vault's sync ingest asks no use limit, so a carrier a device sent
//! before it landed the marker still lands on the hosted copy, as it does today.
//!
//! Named limit of round 2 P1 3: a use limit that takes effect between a window's NOTE refresh
//! and its withholding pass is a race no public door can stage; the pass drops a limited NOTE's
//! workflow rows itself (`note::drop_workflows`), so the export carries no fork text either way.
//! Round 2 P1 5 (a live send the release door withholds asks the socket's peer for a fresh
//! exchange) is server code, outside this crate's test.
//!
//! All nine run red at main f75de13fe4c, whose owner window and owner lane ask no use limit, and
//! green at the fix. The three round-1 tests also run red at the first head 3629c6dd410; the edge
//! test (at its marker line) and the two new round-2 tests run red at the round-1 fix head
//! a020635561b.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_window_withholds_use_limited_rows`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::note::NoteProgramEdit;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::{Materializer, format_edge_key};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, UpdateVerdict, WindowExport};
use oneiron::sync::{WindowManager, documents};
use oneiron::test_doors::source_audience_binding;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, HostingPrivacyPosture, Vad, Vault, VaultConfig, WriteActor,
};

use crate::sync_harness::{
    T0, TestNode, WINDOW, make_entity_blob, map_entries, map_get_bytes, sync_through_doors,
    test_config,
};

const KEPT_WORDS: &[u8] = b"a kept person";
const OTHER_WORDS: &[u8] = b"another person";
const NOTE_TEXT: &str = "Minutes of the harbour board.";
const FORK_TEXT: &str = "Minutes of the harbour board, with the pilot's name.";
/// The month after [`WINDOW`]: 2026-04-02 00:00 UTC.
const NEXT_WINDOW: &str = "2026-04";
const NEXT_T0: u64 = 1_775_088_000;

fn hosted_config() -> VaultConfig {
    let mut config = test_config();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: owner proof")
}

/// Mints this install's machine id, as a paired machine holds one: a withholding marker names
/// the machine that filed it, and a holder lifts a marker that names itself.
fn mint_machine_id(vault: &Vault) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .local_session_key(owner)
        .expect("FIXTURE: mint the machine id");
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited on this hosted vault.
fn keep_use_limited(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-owner-window".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&record)
        .expect("FIXTURE: preview the privacy erase");
    let outcome = memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault
            .legal_hold_use_limit(&record)
            .expect("FIXTURE: read the use limit")
            .is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
}

/// A hosted hub and an own device whose shared window carries a row the hub then keeps under a
/// use limit, and another row.
struct Shared {
    hub: TestNode,
    device: TestNode,
    kept: EntityId,
    other: EntityId,
}

fn shared_then_kept() -> Shared {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let mut device = TestNode::new("device", 1);
    mint_machine_id(&device.vault);
    device.open_window(WINDOW);
    let kept = EntityId::now();
    let other = EntityId::now();
    hub.put_entity_in_window(
        WINDOW,
        &kept,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, KEPT_WORDS),
    );
    hub.put_entity_in_window(
        WINDOW,
        &other,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0 + 1, OTHER_WORDS),
    );
    sync_through_doors(&hub, &mut device);
    assert!(
        device
            .vault
            .get_raw(&kept)
            .expect("FIXTURE: read the device row")
            .is_some(),
        "FIXTURE: the device holds the row before the keep"
    );

    keep_use_limited(&hub.vault, kept);
    Shared {
        hub,
        device,
        kept,
        other,
    }
}

/// The hub's export door answers the device's version, as a sync connection's next round does,
/// and the device lands it.
fn deliver(hub: &TestNode, device: &mut TestNode) {
    let key = WindowKey::new(WINDOW);
    let device_vv = device.doc(WINDOW).oplog_vv().encode();
    match window::export_window_updates_since(&hub.vault, &key, hub.doc(WINDOW), &device_vv)
        .expect("the hub's export door answers")
    {
        WindowExport::Update(update) => {
            device
                .doc(WINDOW)
                .import(&update)
                .expect("the device lands the hub's update");
        }
        WindowExport::Replacement(snapshot) => {
            device.install_replacement(&snapshot);
        }
    }
    sync_through_doors(hub, device);
}

fn carries(node: &TestNode, id: &EntityId) -> bool {
    map_get_bytes(&node.doc(WINDOW).get_map("entities"), &id.to_hex()).is_some()
}

fn withheld_marker(node: &TestNode, id: &EntityId) -> bool {
    map_get_bytes(
        &node.doc(WINDOW).get_map("source_audiences"),
        &format!("withheld/{}", id.to_hex()),
    )
    .is_some()
}

#[test]
fn a_kept_row_leaves_the_owner_window_and_the_device_holds_it_back() {
    let Shared {
        hub,
        mut device,
        kept,
        other,
    } = shared_then_kept();

    deliver(&hub, &mut device);

    assert!(
        !carries(&hub, &kept),
        "the hub's window no longer carries the kept row"
    );
    assert!(
        hub.vault
            .legal_hold_use_limit(&kept)
            .expect("read the use limit")
            .is_some(),
        "the hub keeps its stored copy under the use limit"
    );
    assert!(
        withheld_marker(&hub, &kept),
        "the hub's window carries a withholding marker for the kept row"
    );
    assert!(
        !carries(&device, &kept),
        "the device's window no longer carries the kept row: a restore from it lacks the row"
    );
    assert!(
        withheld_marker(&device, &kept),
        "the device's window landed the withholding marker"
    );
    let device_owner = device
        .vault
        .ensure_embedded_owner_actor()
        .expect("the device owner");
    assert!(
        !source_audience_binding::reads(&device.vault, kept, &[device_owner]).expect("read walk"),
        "the kept row reads to no one on the device, its owner included"
    );
    assert!(
        !source_audience_binding::travels(&device.vault, kept).expect("replication walk"),
        "the device's own packing never sends the kept row back, so a local edit stays local"
    );
    assert!(
        carries(&device, &other) && carries(&hub, &other),
        "the other row rides as before"
    );
    assert!(
        source_audience_binding::reads(&device.vault, other, &[device_owner]).expect("read walk"),
        "the other row reads on the device as before"
    );
}

#[test]
fn a_peer_behind_the_kept_row_takes_a_replacement_without_it() {
    let Shared {
        hub,
        mut device,
        kept,
        other,
    } = shared_then_kept();
    deliver(&hub, &mut device);

    let key = WindowKey::new(WINDOW);
    let nothing = VersionVector::default().encode();
    assert!(
        matches!(
            window::export_window_updates_since(&hub.vault, &key, hub.doc(WINDOW), &nothing)
                .expect("the hub's export door answers"),
            WindowExport::Replacement(_)
        ),
        "a peer that holds nothing of the window takes a history-free replacement"
    );

    let mut fresh = TestNode::new("fresh-device", 3);
    mint_machine_id(&fresh.vault);
    fresh.open_window(WINDOW);
    sync_through_doors(&hub, &mut fresh);
    assert!(
        carries(&fresh, &other) && fresh.vault.get_raw(&other).expect("read").is_some(),
        "the fresh device holds the other row"
    );
    assert!(
        !carries(&fresh, &kept),
        "the fresh device's window never carried the kept row"
    );
    assert!(
        fresh.vault.get_raw(&kept).expect("read").is_none(),
        "the fresh device holds no byte of the kept row"
    );
}

#[test]
fn the_owner_lane_sends_no_text_of_a_kept_note() {
    let dir = tempfile::tempdir().expect("FIXTURE: hosted vault dir");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let source = Arc::new(Vault::open(dir.path(), config).expect("FIXTURE: open the hosted vault"));
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    source
        .prepare_install_signing()
        .expect("FIXTURE: load the install signer");
    let author = WriteActor::new(
        source
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the vault names its embedded owner actor"),
        EdgeActorClass::Human,
    );
    let manager = Arc::new(WindowManager::new(
        source.clone(),
        Arc::new(Materializer::new()),
        "authority",
    ));
    let note = source
        .create_note("research", NOTE_TEXT, author)
        .expect("FIXTURE: the hosted vault writes a NOTE");
    let nothing = VersionVector::default().encode();
    let frame = manager
        .export_owner_document(note, &nothing)
        .expect("FIXTURE: the owner lane exports the NOTE before the keep");
    assert!(
        !documents::document_frame_withheld(&source, &frame),
        "FIXTURE: the NOTE's frame releases before the keep"
    );

    keep_use_limited(&source, note);

    let refused = manager
        .export_owner_document(note, &nothing)
        .expect_err("the owner lane refuses the kept NOTE's text");
    assert!(
        format!("{refused:?}").contains("DocumentAdmissionDenied"),
        "the refusal is the owner lane's admission denial: {refused:?}"
    );
    assert!(
        documents::document_frame_withheld(&source, &frame),
        "a frame queued before the keep is withheld at release"
    );
}

#[test]
fn an_already_synced_device_installs_a_replacement_without_the_kept_row() {
    let Shared {
        hub,
        mut device,
        kept,
        other,
    } = shared_then_kept();
    let key = WindowKey::new(WINDOW);
    let snapshot = window::export_window_replacement(&hub.vault, &key, hub.doc(WINDOW), None)
        .expect("the hub's replacement door answers")
        .expect("the hub withholds no window from its own device");
    assert!(
        carries(&device, &kept),
        "FIXTURE: the device's window carries the kept row until the replacement"
    );

    device.install_replacement(&snapshot);

    assert!(
        !carries(&device, &kept),
        "the installed window does not carry the kept row back from the device's store"
    );
    assert!(
        withheld_marker(&device, &kept),
        "the installed window carries the hub's withholding marker"
    );
    let device_owner = device
        .vault
        .ensure_embedded_owner_actor()
        .expect("the device owner");
    assert!(
        !source_audience_binding::reads(&device.vault, kept, &[device_owner]).expect("read walk"),
        "the kept row reads to no one on the device"
    );
    assert!(carries(&device, &other), "the other row rides as before");
}

/// The hub's export door answers the device's version of window `key`, and the device lands it:
/// an update it imports, a replacement it installs.
fn deliver_window(hub: &TestNode, device: &mut TestNode, key: &str) {
    let window_key = WindowKey::new(key);
    let device_vv = device.doc(key).oplog_vv().encode();
    match window::export_window_updates_since(&hub.vault, &window_key, hub.doc(key), &device_vv)
        .expect("the hub's export door answers")
    {
        WindowExport::Update(update) => {
            device
                .doc(key)
                .import(&update)
                .expect("the device lands the hub's update");
        }
        WindowExport::Replacement(snapshot) => {
            device.install_replacement_of(key, &snapshot);
        }
    }
}

#[test]
fn a_device_holding_a_kept_note_back_never_packs_it_again() {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    let mut device = TestNode::new("device", 1);
    mint_machine_id(&device.vault);
    let author = WriteActor::new(
        hub.vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the hub names its embedded owner actor"),
        EdgeActorClass::Human,
    );
    let note = hub
        .vault
        .create_note("research", NOTE_TEXT, author)
        .expect("FIXTURE: the hub writes a NOTE");
    let key = WindowKey::from_timestamp(hub.vault.now_recorded_at());
    let month = key.as_str().to_owned();
    hub.open_window(&month);
    device.open_window(&month);
    deliver_window(&hub, &mut device, &month);
    let carries_note =
        |node: &TestNode| map_get_bytes(&node.doc(&month).get_map("entities"), &note.to_hex());
    assert!(
        carries_note(&device).is_some()
            && device
                .vault
                .get_raw(&note)
                .expect("FIXTURE: read the device's NOTE")
                .is_some(),
        "FIXTURE: the device's window carries the NOTE and the device stores it before the keep"
    );

    keep_use_limited(&hub.vault, note);
    deliver_window(&hub, &mut device, &month);
    let device_owner = device
        .vault
        .ensure_embedded_owner_actor()
        .expect("the device owner");
    assert!(
        carries_note(&device).is_none()
            && !source_audience_binding::reads(&device.vault, note, &[device_owner])
                .expect("read walk"),
        "FIXTURE: the device landed the marker: its window lost the NOTE, which reads to no one"
    );

    let nothing = VersionVector::default().encode();
    let sent = match window::export_window_updates_since(
        &device.vault,
        &key,
        device.doc(&month),
        &nothing,
    )
    .expect("the device's export door answers")
    {
        WindowExport::Update(update) => update,
        WindowExport::Replacement(snapshot) => snapshot,
    };
    assert!(
        carries_note(&device).is_none(),
        "the device's NOTE refresh never packs the held-back NOTE into its window again"
    );
    assert!(
        !holds_text(device.doc(&month), NOTE_TEXT),
        "the device's window carries no byte of the held-back NOTE's text"
    );
    let alone = LoroDoc::new();
    alone
        .import(&sent)
        .expect("the device's export imports on its own");
    assert!(
        map_get_bytes(&alone.get_map("entities"), &note.to_hex()).is_none(),
        "the device's export ships no carrier of the held-back NOTE"
    );
}

fn hosted_vault_with_manager(dir: &tempfile::TempDir) -> (Arc<Vault>, Arc<WindowManager>) {
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("FIXTURE: open the hosted vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: load the install signer");
    let manager = Arc::new(WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "authority",
    ));
    (vault, manager)
}

/// Whether any map of `doc` holds a value that contains `text`'s bytes.
fn holds_text(doc: &LoroDoc, text: &str) -> bool {
    let needle = text.as_bytes();
    let maps: Vec<String> = match doc.get_deep_value() {
        loro::LoroValue::Map(roots) => roots.iter().map(|(name, _)| name.clone()).collect(),
        _ => Vec::new(),
    };
    maps.iter().any(|name| {
        map_entries(&doc.get_map(name.as_str()))
            .values()
            .any(|value| value.windows(needle.len()).any(|part| part == needle))
    })
}

#[test]
fn a_send_queued_before_the_keep_is_withheld_at_release() {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let kept = EntityId::now();
    let other = EntityId::now();
    hub.put_entity_in_window(
        WINDOW,
        &kept,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, KEPT_WORDS),
    );
    hub.put_entity_in_window(
        WINDOW,
        &other,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0 + 1, OTHER_WORDS),
    );
    let queued = hub
        .doc(WINDOW)
        .export(ExportMode::all_updates())
        .expect("FIXTURE: the window's updates, as a live send queues them");
    let manager = Arc::new(WindowManager::new(
        hub.vault.clone(),
        Arc::new(Materializer::new()),
        "authority",
    ));
    assert_eq!(
        window::raw_update_verdict(&manager, WINDOW, &queued),
        UpdateVerdict::Portable,
        "FIXTURE: the send releases before the keep"
    );

    keep_use_limited(&hub.vault, kept);

    assert_eq!(
        window::raw_update_verdict(&manager, WINDOW, &queued),
        UpdateVerdict::Withheld,
        "a send queued before the keep ships no carrier of the kept row after it"
    );
    let key = WindowKey::new(WINDOW);
    let nothing = VersionVector::default().encode();
    let sent =
        match window::export_window_updates_since(&hub.vault, &key, hub.doc(WINDOW), &nothing)
            .expect("the hub's export door answers")
        {
            WindowExport::Update(update) => update,
            WindowExport::Replacement(snapshot) => snapshot,
        };
    assert!(
        withheld_marker(&hub, &kept),
        "the scrubbed window carries the withholding marker"
    );
    assert_eq!(
        window::raw_update_verdict(&manager, WINDOW, &sent),
        UpdateVerdict::Portable,
        "the scrubbed export, which carries the marker and no carrier of the row, still sends"
    );
}

#[test]
fn an_edge_naming_a_kept_row_carried_elsewhere_leaves_the_window() {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    hub.open_window(NEXT_WINDOW);
    let kept = EntityId::now();
    let other = EntityId::now();
    hub.put_entity_in_window(
        NEXT_WINDOW,
        &kept,
        &make_entity_blob(ENTITY_TYPE_PERSON, NEXT_T0, KEPT_WORDS),
    );
    hub.put_entity_in_window(
        WINDOW,
        &other,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, OTHER_WORDS),
    );
    hub.put_edge_in_window(
        WINDOW,
        &other,
        EdgeKind::Mentions,
        &kept,
        0.5,
        T0 + 1,
        Vad::NEUTRAL,
    );
    let edge = format_edge_key(&other, EdgeKind::Mentions, &kept);
    assert!(
        !carries(&hub, &kept) && map_get_bytes(&hub.doc(WINDOW).get_map("edges"), &edge).is_some(),
        "FIXTURE: the window carries the edge, and the kept row's carrier rides elsewhere"
    );

    keep_use_limited(&hub.vault, kept);
    let key = WindowKey::new(WINDOW);
    let nothing = VersionVector::default().encode();
    window::export_window_updates_since(&hub.vault, &key, hub.doc(WINDOW), &nothing)
        .expect("the hub's export door answers");

    assert!(
        map_get_bytes(&hub.doc(WINDOW).get_map("edges"), &edge).is_none(),
        "the window no longer carries the edge to the kept row"
    );
    assert!(
        !withheld_marker(&hub, &kept),
        "a window that names the kept row only in an edge files no marker for it, so it never \
         holds the row back once the limit lifts"
    );
    assert!(
        carries(&hub, &other),
        "the edge's other row rides as before"
    );
    let next = WindowKey::new(NEXT_WINDOW);
    window::export_window_updates_since(&hub.vault, &next, hub.doc(NEXT_WINDOW), &nothing)
        .expect("the hub's export door answers");
    assert!(
        map_get_bytes(&hub.doc(NEXT_WINDOW).get_map("entities"), &kept.to_hex()).is_none(),
        "the kept row's own window no longer carries it"
    );
    assert!(
        map_get_bytes(
            &hub.doc(NEXT_WINDOW).get_map("source_audiences"),
            &format!("withheld/{}", kept.to_hex()),
        )
        .is_some(),
        "the kept row's own window carries its withholding marker"
    );
}

#[test]
fn a_kept_notes_pending_fork_text_leaves_the_window() {
    let dir = tempfile::tempdir().expect("FIXTURE: hosted vault dir");
    let (vault, manager) = hosted_vault_with_manager(&dir);
    let author = || {
        WriteActor::new(
            vault
                .ensure_embedded_owner_actor()
                .expect("FIXTURE: the vault names its embedded owner actor"),
            EdgeActorClass::Human,
        )
    };
    let note = vault
        .create_note("research", NOTE_TEXT, author())
        .expect("FIXTURE: the hosted vault writes a NOTE");
    vault
        .fork_note(
            note,
            &NoteProgramEdit::Rewrite {
                text: FORK_TEXT.to_owned(),
            },
            author(),
        )
        .expect("FIXTURE: the owner forks the NOTE, undecided");
    let key = WindowKey::from_timestamp(vault.now_recorded_at());
    let window = manager.open_window(&key).expect("FIXTURE: open the window");
    let nothing = VersionVector::default().encode();
    window::export_window_updates_since(&vault, &key, &window.doc, &nothing)
        .expect("FIXTURE: the export door answers before the keep");
    assert!(
        holds_text(&window.doc, FORK_TEXT),
        "FIXTURE: before the keep the window packs the undecided fork's text"
    );

    keep_use_limited(&vault, note);
    window::export_window_updates_since(&vault, &key, &window.doc, &nothing)
        .expect("the export door answers after the keep");

    assert!(
        !holds_text(&window.doc, FORK_TEXT),
        "the window carries no byte of the kept NOTE's fork text"
    );
    assert!(
        map_get_bytes(&window.doc.get_map("entities"), &note.to_hex()).is_none(),
        "the window no longer carries the kept NOTE"
    );
    assert!(
        map_get_bytes(
            &window.doc.get_map("source_audiences"),
            &format!("withheld/{}", note.to_hex()),
        )
        .is_some(),
        "the window carries a withholding marker for the kept NOTE"
    );
}
