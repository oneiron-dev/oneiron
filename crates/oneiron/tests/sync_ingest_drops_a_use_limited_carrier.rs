//! A hosted vault drops a device's carrier for a row a refused privacy erase keeps for storage
//! only, and lands the rest of what the device sent (FIX
//! SYNC-INGEST-LANDS-CARRIER-OVER-USE-LIMITED-ROW).
//!
//! A record a customer hold keeps from a privacy erase (C6) takes no named change on the hosted
//! vault: the put door refuses it as absent (OF-470 C6). A device that edited the row before the
//! keep reached it still sends its carrier. The sync ingest handed that carrier to the put door,
//! and the door's refusal read as a local failure: the hub's whole entity batch aborted, so the
//! other rows of the same delta never landed, and the window's forward rematerialization failed,
//! so the hub could not recover the window. The ingest now drops the carrier the way the put door
//! refuses a named write: the kept copy stays as it is, and the rest lands.
//!
//! * `a_device_edit_of_the_kept_row_leaves_the_kept_copy_and_the_rest_lands`: the device sends,
//!   in one delta, an edit of the kept row and a new row. The hub lands the new row and keeps its
//!   stored copy of the kept row byte for byte, still under the use limit.
//! * `the_hub_recovers_a_window_that_carries_a_device_edit_of_the_kept_row`: the hub persists and
//!   recovers that window, whose entities map now carries the device's edit; the recovery's
//!   forward rematerialization passes, and the kept copy stays as it is.
//! * `a_device_edit_dropped_under_a_restriction_stays_out_after_the_lift`: a cooperative review
//!   restricts the row instead, and the device's edit arrives while it stands. The review lifts
//!   the restriction without rewriting the row, and the hub recovers the window, whose entities
//!   map still carries the dropped edit: the hub keeps its stored copy (REVIEW-9881 round 1).
//! * `a_device_receipt_carrier_at_the_kept_row_leaves_the_kept_copy_and_the_rest_lands`: the
//!   device sends, at the kept row's id, an envelope-valid served-form receipt record beside a new
//!   row. Its receipt binds the id, not the kind stored there, so it takes the receipt door, whose
//!   put would refuse it as absent. The hub drops it as it drops any other carrier of the row, and
//!   the new row lands (REVIEW-9881 round 1).
//! * `a_birth_carried_for_the_restricted_row_is_not_stamped_before_or_after_the_lift`: the device
//!   sends, in one delta, an edit of a restricted row the hub holds with no birth and a well-formed
//!   birth for it. Neither the entity pass nor the birth-map observer stamps the birth while the
//!   restriction stands, and the forward rematerialization after the lift does not either: the
//!   carrier the birth rides beside was dropped (REVIEW-9881 round 1).
//! * `a_note_edit_dropped_under_a_restriction_at_the_purge_fence_stays_out_after_the_drain`: the
//!   device's header edit of a NOTE arrives while a cooperative review restricts it and an
//!   unproven purge retry fences it. The hub makes the update durable, the review lifts and the
//!   purge proof settles the NOTE's marker, and the marker drain rematerializes the window from
//!   the hub's update rows, whose entities map still carries the edit: the hub keeps its stored
//!   NOTE (REVIEW-9881 round 2). The drain is the path that reaches it: a persist, an export door
//!   and a cold open's reverse pass each pack the stored NOTE core over the window's carrier first.
//!
//! The first two run red at main 6f0800329f2, whose ingest hands the carrier to the put door, and
//! green at the fix. The third runs red at ca7a0807956, whose ingest drops the carrier only while
//! the restriction stands, so the recovery after the lift puts it, and green at the round-1 fix.
//! The fourth runs red where the receipt branch hands the carrier to the receipt door without the
//! drop, and green at main. The fifth runs red before the lift where the birth gate leaves out
//! both its limit conjuncts (or where the entity pass or the birth-map observer alone skips the
//! gate's limit conjuncts), red after the lift where it leaves out only the dropped-carrier
//! conjunct, and green at main. The sixth runs red where the drop is asked below the NOTE purge
//! fence (the round-1 order 61609b9a3d2 moved), whose skip records no digest, so the drain puts
//! the edit, and green at main.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sync_ingest_drops_a_use_limited_carrier`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::note::{NoteActor, NoteCore, NoteKind, encode_note_core};
use oneiron::provenance::birth::RowBirth;
use oneiron::receipt::{ReceiptKind, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON, ENTITY_TYPE_RECEIPT_RECORD};
use oneiron::store::GateDecisionId;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::sync::{drain_remat_markers, export_updates_since, server_state};
use oneiron::test_doors::campaign_member_index::{lift_restriction, restrict_record};
use oneiron::test_doors::media_vector_replica::stored_row;
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_store::receipt_ref::ReceiptRef;
use std::collections::BTreeMap;

use crate::sync_harness::{
    ENTITY_METADATA_HEADER_LEN, T0, TestNode, WINDOW, make_entity_blob, map_get_bytes,
    map_insert_bytes, sync_through_doors, test_config,
};

const KEPT_WORDS: &[u8] = b"a kept person";
const EDITED_WORDS: &[u8] = b"a kept person, edited on the device";
const NEW_WORDS: &[u8] = b"a person the device met later";

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

/// Mints this install's machine id, as a paired machine holds one: a withholding marker the
/// hub files (once its owner window withholds the kept row) names the machine that filed it.
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
            Some("matter-sync-ingest".to_owned()),
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

/// Restricts `record` under a cooperative review, in the row the cooperative-deletion answer
/// writes: the hub takes no named change to it until the review lifts the restriction.
fn restrict(vault: &Vault, record: EntityId) {
    restrict_record(vault, record).expect("FIXTURE: restrict the record");
}

/// [`restrict`], for a row the hub holds with no birth of its own: a window put stamps none.
fn restrict_row_without_birth(vault: &Vault, record: EntityId) {
    assert!(
        vault
            .row_birth(&record)
            .expect("FIXTURE: read the hub's row birth")
            .is_none(),
        "FIXTURE: the hub holds the row with no birth of its own"
    );
    restrict(vault, record);
}

/// A served-form record at `id`, as a peer's window carries one: an image served to a holder at
/// `at`, in the carrier the record door writes (`{receipt}`, no intent id). Its receipt binds the
/// id alone, never the kind stored there, so it passes the receipt door's envelope check at the
/// id of a PERSON row.
fn served_form_carrier(id: &EntityId, at: u64) -> Vec<u8> {
    let receipt = ReceiptRecord {
        receipt_id: ReceiptRef::served_form(*id).to_string(),
        receipt_kind: ReceiptKind::ServedForm,
        occurred_at: at,
        actor: Some(EntityId::now().to_hex()),
        on_behalf_of: None,
        outcome: "served".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: BTreeMap::from([
            ("asset_ref".to_owned(), EntityId::now().to_hex()),
            ("form".to_owned(), "image".to_owned()),
        ]),
    };
    let body = rmp_serde::to_vec_named(&BTreeMap::from([("receipt", &receipt)]))
        .expect("FIXTURE: the served-form carrier encodes");
    make_entity_blob(ENTITY_TYPE_RECEIPT_RECORD, at, &body)
}

/// One canonical row birth, as a window's `row_births` map carries it: stated by a fresh actor,
/// with no trigger and no input.
fn row_birth_carrier() -> Vec<u8> {
    let birth = RowBirth {
        made_by: MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: EntityId::now(),
                class: MadeByClass::Stated,
                identity: "device-birth-fixture".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: T0,
            trigger: None,
        },
        content_hash: String::new(),
        withheld: Vec::new(),
        room_evidence: None,
    };
    rmp_serde::to_vec_named(&birth).expect("FIXTURE: the row birth encodes")
}

/// A hosted hub and an own device whose shared window carries a row the hub then limits, and
/// the device's edit of that row, sent with a new row in one delta before the hub answered the
/// device again.
struct Sent {
    hub: TestNode,
    kept: EntityId,
    kept_copy: Vec<u8>,
    new_row: EntityId,
}

/// What the device sends for the hub's limited row: its carrier of the row, and the birth it
/// carries for the row beside it, if any.
struct DeviceSend {
    carrier: Vec<u8>,
    birth: Option<Vec<u8>>,
}

fn device_edit_sent_after_the_keep() -> Sent {
    device_edit_sent_after(keep_use_limited)
}

/// [`Sent`], with `limit` placed on the hub's row before the device edits it.
fn device_edit_sent_after(limit: fn(&Vault, EntityId)) -> Sent {
    device_sent_after(limit, |_| DeviceSend {
        carrier: make_entity_blob(ENTITY_TYPE_PERSON, T0 + 5, EDITED_WORDS),
        birth: None,
    })
}

/// [`Sent`], with `limit` placed on the hub's row before the device sends `send`'s carrier of it
/// (and its birth) beside the new row.
fn device_sent_after(
    limit: fn(&Vault, EntityId),
    send: impl FnOnce(&EntityId) -> DeviceSend,
) -> Sent {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let mut device = TestNode::new("device", 1);
    mint_machine_id(&device.vault);
    device.open_window(WINDOW);
    let kept = EntityId::now();
    hub.put_entity_in_window(
        WINDOW,
        &kept,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, KEPT_WORDS),
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

    limit(&hub.vault, kept);
    let kept_copy = stored_row(&hub.vault, &kept)
        .expect("FIXTURE: read the hub's stored row")
        .expect("FIXTURE: the hub stores the kept row");

    // The device has not heard of the limit: it sends its carrier of the row (and a birth for
    // it) and meets a new person, in one commit, so all of it travels in one delta.
    let new_row = EntityId::now();
    let DeviceSend { carrier, birth } = send(&kept);
    let entities = device.doc(WINDOW).get_map("entities");
    map_insert_bytes(&entities, &kept.to_hex(), &carrier);
    map_insert_bytes(
        &entities,
        &new_row.to_hex(),
        &make_entity_blob(ENTITY_TYPE_PERSON, T0 + 6, NEW_WORDS),
    );
    if let Some(birth) = birth {
        map_insert_bytes(
            &device.doc(WINDOW).get_map("row_births"),
            &kept.to_hex(),
            &birth,
        );
    }
    device.doc(WINDOW).commit();
    assert!(
        device
            .vault
            .get_raw(&new_row)
            .expect("FIXTURE: read the device's new row")
            .is_some(),
        "FIXTURE: the device lands its new row"
    );

    // The device's export door answers the hub's version, as the device's next send does.
    let key = WindowKey::new(WINDOW);
    let hub_version = hub.doc(WINDOW).oplog_vv().encode();
    match window::export_window_updates_since(&device.vault, &key, device.doc(WINDOW), &hub_version)
        .expect("FIXTURE: the device's export door answers")
    {
        WindowExport::Update(update) => {
            hub.doc(WINDOW)
                .import(&update)
                .expect("the hub imports the device's update");
        }
        WindowExport::Replacement(_) => {
            panic!("FIXTURE: the device's door answers the hub with an update")
        }
    }
    Sent {
        hub,
        kept,
        kept_copy,
        new_row,
    }
}

fn assert_kept_copy_stays(hub: &TestNode, kept: &EntityId, kept_copy: &[u8]) {
    assert_eq!(
        stored_row(&hub.vault, kept)
            .expect("read the hub's stored row")
            .as_deref(),
        Some(kept_copy),
        "the hub keeps its stored copy of the kept row byte for byte"
    );
    assert!(
        hub.vault
            .legal_hold_use_limit(kept)
            .expect("read the use limit")
            .is_some(),
        "the kept row stays under its use limit"
    );
}

#[test]
fn a_device_edit_of_the_kept_row_leaves_the_kept_copy_and_the_rest_lands() {
    let Sent {
        hub,
        kept,
        kept_copy,
        new_row,
    } = device_edit_sent_after_the_keep();

    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "the new row the device sent beside its edit of the kept row lands on the hub"
    );
    assert_kept_copy_stays(&hub, &kept, &kept_copy);
}

#[test]
fn the_hub_recovers_a_window_that_carries_a_device_edit_of_the_kept_row() {
    let Sent {
        mut hub,
        kept,
        kept_copy,
        new_row,
    } = device_edit_sent_after_the_keep();

    // Persist, reload and rematerialize the window, as the hub's next open does.
    hub.recover(WINDOW);

    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "the recovered window's new row stands on the hub"
    );
    assert_kept_copy_stays(&hub, &kept, &kept_copy);
}

#[test]
fn a_device_edit_dropped_under_a_restriction_stays_out_after_the_lift() {
    let Sent {
        mut hub,
        kept,
        kept_copy,
        new_row,
    } = device_edit_sent_after(restrict);
    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "FIXTURE: the new row the device sent beside its edit of the restricted row lands"
    );
    assert_eq!(
        stored_row(&hub.vault, &kept)
            .expect("read the hub's stored row")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "FIXTURE: while the restriction stands the hub keeps its stored copy"
    );

    // The review lifts the restriction and does not rewrite the row; the hub's next open
    // rematerializes the window, whose entities map still carries the dropped edit.
    lift_restriction(&hub.vault, kept).expect("FIXTURE: lift the restriction");
    hub.recover(WINDOW);

    assert_eq!(
        stored_row(&hub.vault, &kept)
            .expect("read the hub's stored row")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "an edit the hub dropped while the record was restricted does not land once the restriction lifts"
    );
    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "the recovered window's new row stands on the hub"
    );
}

#[test]
fn a_device_receipt_carrier_at_the_kept_row_leaves_the_kept_copy_and_the_rest_lands() {
    let Sent {
        hub,
        kept,
        kept_copy,
        new_row,
    } = device_sent_after(keep_use_limited, |kept| DeviceSend {
        carrier: served_form_carrier(kept, T0 + 5),
        birth: None,
    });

    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "the new row the device sent beside its receipt carrier at the kept row lands on the hub"
    );
    assert_kept_copy_stays(&hub, &kept, &kept_copy);
}

#[test]
fn a_birth_carried_for_the_restricted_row_is_not_stamped_before_or_after_the_lift() {
    let Sent {
        mut hub,
        kept,
        kept_copy,
        new_row,
    } = device_sent_after(restrict_row_without_birth, |_| DeviceSend {
        carrier: make_entity_blob(ENTITY_TYPE_PERSON, T0 + 5, EDITED_WORDS),
        birth: Some(row_birth_carrier()),
    });
    assert!(
        hub.vault
            .get_raw(&new_row)
            .expect("read the hub's new row")
            .is_some(),
        "FIXTURE: the new row the device sent beside its edit and birth lands"
    );
    assert_eq!(
        stored_row(&hub.vault, &kept)
            .expect("read the hub's stored row")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "FIXTURE: while the restriction stands the hub keeps its stored copy"
    );
    assert!(
        hub.vault
            .row_birth(&kept)
            .expect("read the hub's row birth")
            .is_none(),
        "a birth the device carried beside its dropped edit of the restricted row is not stamped on it"
    );

    // The review lifts the restriction; the hub's next open rematerializes the window, whose maps
    // still carry the dropped edit and the birth beside it.
    lift_restriction(&hub.vault, kept).expect("FIXTURE: lift the restriction");
    hub.recover(WINDOW);

    assert!(
        hub.vault
            .row_birth(&kept)
            .expect("read the hub's row birth")
            .is_none(),
        "a birth riding beside a carrier the hub dropped is not stamped once the restriction lifts"
    );
    assert_eq!(
        stored_row(&hub.vault, &kept)
            .expect("read the hub's stored row")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "the hub keeps its stored copy after the lift"
    );
}

/// The `rm:w:` row that holds `id` behind a purge retry in [`WINDOW`], and the replay-provenance
/// sidecar beside it (`sync/quarantine/remat_markers.rs`). A marker with no sidecar is an
/// unproven one: a NOTE carrier waits at the purge fence while it stands.
fn purge_marker_keys(id: &EntityId) -> (String, String) {
    (
        format!("rm:w:{WINDOW}:{}", id.to_hex()),
        format!("rmp:w:{WINDOW}:{}", id.to_hex()),
    )
}

/// Holds `id` behind an unproven purge retry in [`WINDOW`], as a failed CRDT-tombstone purge
/// leaves it.
fn set_unproven_purge_marker(vault: &Vault, id: &EntityId) {
    let (marker, _) = purge_marker_keys(id);
    vault
        .sync_state_put(&marker, &[1])
        .expect("FIXTURE: set the unproven purge marker");
}

/// Settles `id`'s purge retry in [`WINDOW`], as its purge proof does: the marker and its sidecar
/// go, and the row stays stored.
fn settle_purge_marker(vault: &Vault, id: &EntityId) {
    let (marker, provenance) = purge_marker_keys(id);
    vault
        .sync_state_delete(&marker)
        .expect("FIXTURE: clear the purge marker");
    vault
        .sync_state_delete(&provenance)
        .expect("FIXTURE: clear the purge marker's provenance");
}

#[test]
fn a_note_edit_dropped_under_a_restriction_at_the_purge_fence_stays_out_after_the_drain() {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let mut device = TestNode::new("device", 1);
    mint_machine_id(&device.vault);
    device.open_window(WINDOW);
    let key = WindowKey::new(WINDOW);

    // The hub stores a NOTE in the window: its row is the NOTE core alone.
    let note = EntityId::now();
    let owner = hub
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the hub names its embedded owner actor");
    let core = encode_note_core(&NoteCore {
        kind: NoteKind::OpinionTake,
        author_ref: NoteActor::Actor(owner),
        source_revision_ref: [0x42; 16],
    })
    .expect("FIXTURE: the NOTE core encodes");
    hub.put_entity_in_window(
        WINDOW,
        &note,
        &make_entity_blob(ENTITY_TYPE_NOTE, T0, &core),
    );
    let kept_copy = stored_row(&hub.vault, &note)
        .expect("FIXTURE: read the hub's stored NOTE")
        .expect("FIXTURE: the hub stores the NOTE");

    // The device takes the hub's window op as it is. An export door packs the stored NOTE core
    // over the carrier it sends, and the device's edit must follow the op the hub's durable rows
    // hold.
    let seed = export_updates_since(hub.doc(WINDOW), &device.doc(WINDOW).oplog_vv().encode())
        .expect("FIXTURE: export the hub's NOTE op");
    let imported = device
        .doc(WINDOW)
        .import(&seed)
        .expect("FIXTURE: the device imports the hub's NOTE op");
    assert!(
        imported.pending.is_none(),
        "FIXTURE: the device holds every op the hub's NOTE op follows"
    );
    assert_eq!(
        stored_row(&device.vault, &note)
            .expect("FIXTURE: read the device's stored NOTE")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "FIXTURE: the device holds the hub's NOTE"
    );

    // A cooperative review restricts the NOTE, and its purge retry is not proven yet.
    restrict(&hub.vault, note);
    set_unproven_purge_marker(&hub.vault, &note);

    // The device has heard of neither: it changes the NOTE's metadata header and keeps its core,
    // which a NOTE birth may not change.
    let edited = make_entity_blob(
        ENTITY_TYPE_NOTE,
        T0 + 5,
        &kept_copy[ENTITY_METADATA_HEADER_LEN..],
    );
    assert_ne!(
        edited, kept_copy,
        "FIXTURE: the edit changes the NOTE's header"
    );
    device.put_entity_in_window(WINDOW, &note, &edited);
    assert_ne!(
        stored_row(&device.vault, &note)
            .expect("FIXTURE: read the device's edited NOTE")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "FIXTURE: the header edit is a write on the unrestricted device"
    );

    // The hub admits the device's update and makes it durable, as its server does, then imports
    // it: the ingest meets the restriction and the purge fence together.
    let update = export_updates_since(device.doc(WINDOW), &hub.doc(WINDOW).oplog_vv().encode())
        .expect("FIXTURE: export the device's edit");
    let inserts = window::admit_window_update_residence_with_vault(
        &hub.vault,
        hub.doc(WINDOW),
        &update,
        &key,
    )
    .expect("FIXTURE: the hub's window admits the device's update");
    server_state::persist_imported_window_update(&hub.vault, &key, &update, &inserts)
        .expect("FIXTURE: the hub persists the device's update");
    let imported = hub
        .doc(WINDOW)
        .import(&update)
        .expect("FIXTURE: the hub imports the device's update");
    assert!(
        imported.pending.is_none(),
        "FIXTURE: the hub holds every op the device's edit follows"
    );
    assert_eq!(
        map_get_bytes(&hub.doc(WINDOW).get_map("entities"), &note.to_hex()).as_deref(),
        Some(edited.as_slice()),
        "FIXTURE: the hub's window carries the device's edit"
    );
    assert_eq!(
        stored_row(&hub.vault, &note)
            .expect("FIXTURE: read the hub's stored NOTE")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "FIXTURE: while the restriction and the purge fence stand the hub keeps its stored NOTE"
    );

    // The review lifts the restriction and the purge proof settles the NOTE's marker, neither
    // rewriting the row. Another entity's unproven purge retry keeps the window flagged, so the
    // marker drain rematerializes it.
    lift_restriction(&hub.vault, note).expect("FIXTURE: lift the restriction");
    settle_purge_marker(&hub.vault, &note);
    set_unproven_purge_marker(&hub.vault, &EntityId::now());

    // No persist, export or reverse pass runs before the drain, so no NOTE refresh packs the
    // stored core over the carrier: the drain loads the window from the hub's update rows.
    assert!(
        !server_state::window_snapshot_present(&hub.vault, &key)
            .expect("FIXTURE: look for the hub's window snapshot"),
        "FIXTURE: the hub holds no window snapshot, so the drain rebuilds the window from its update rows"
    );
    let durable = window::rebuild_window_from_updates(&hub.vault, hub.name, &key)
        .expect("FIXTURE: rebuild the window the drain loads");
    assert_eq!(
        map_get_bytes(&durable.get_map("entities"), &note.to_hex()).as_deref(),
        Some(edited.as_slice()),
        "FIXTURE: the window the drain loads carries the device's edit"
    );
    let report = drain_remat_markers(&hub.vault, hub.name, &hub.materializer)
        .expect("the drain rematerializes the flagged window");
    assert_eq!(
        report.still_pending,
        vec![WINDOW.to_owned()],
        "FIXTURE: the drain rematerialized the window, whose other marker stays: {report:?}"
    );

    assert_eq!(
        stored_row(&hub.vault, &note)
            .expect("read the hub's stored NOTE")
            .as_deref(),
        Some(kept_copy.as_slice()),
        "a NOTE edit the hub dropped under the restriction at the purge fence does not land when the drain rematerializes the window after the lift"
    );
}
