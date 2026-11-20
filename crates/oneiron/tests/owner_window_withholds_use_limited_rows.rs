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
//!
//! Named limits, not tested here: a whole-vault export run on the device still carries the held
//! row's bytes (its egress asks off-record and the device's own use limits, not the source
//! audience hold); the hosted vault's sync ingest asks no use limit, so a carrier a device sent
//! before it landed the marker still lands on the hosted copy, as it does today.
//!
//! All three run red at main f75de13fe4c, whose owner window and owner lane ask no use limit, and
//! green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_window_withholds_use_limited_rows`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use std::sync::Arc;

use loro::VersionVector;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::sync::{WindowManager, documents};
use oneiron::test_doors::source_audience_binding;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig, WriteActor};

use crate::sync_harness::{
    T0, TestNode, WINDOW, make_entity_blob, map_get_bytes, sync_through_doors, test_config,
};

const KEPT_WORDS: &[u8] = b"a kept person";
const OTHER_WORDS: &[u8] = b"another person";
const NOTE_TEXT: &str = "Minutes of the harbour board.";

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
