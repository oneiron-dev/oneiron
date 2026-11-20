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
//!
//! The first two run red at main 6f0800329f2, whose ingest hands the carrier to the put door, and
//! green at the fix. The third runs red at ca7a0807956, whose ingest drops the carrier only while
//! the restriction stands, so the recovery after the lift puts it, and green at the round-1 fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sync_ingest_drops_a_use_limited_carrier`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::test_doors::campaign_member_index::{lift_restriction, restrict_record};
use oneiron::test_doors::media_vector_replica::stored_row;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};

use crate::sync_harness::{
    T0, TestNode, WINDOW, make_entity_blob, map_insert_bytes, sync_through_doors, test_config,
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

/// A hosted hub and an own device whose shared window carries a row the hub then limits, and
/// the device's edit of that row, sent with a new row in one delta before the hub answered the
/// device again.
struct Sent {
    hub: TestNode,
    kept: EntityId,
    kept_copy: Vec<u8>,
    new_row: EntityId,
}

fn device_edit_sent_after_the_keep() -> Sent {
    device_edit_sent_after(keep_use_limited)
}

/// [`Sent`], with `limit` placed on the hub's row before the device edits it.
fn device_edit_sent_after(limit: fn(&Vault, EntityId)) -> Sent {
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

    // The device has not heard of the limit: it edits the row and meets a new person, in one
    // commit, so both travel in one delta.
    let new_row = EntityId::now();
    let entities = device.doc(WINDOW).get_map("entities");
    map_insert_bytes(
        &entities,
        &kept.to_hex(),
        &make_entity_blob(ENTITY_TYPE_PERSON, T0 + 5, EDITED_WORDS),
    );
    map_insert_bytes(
        &entities,
        &new_row.to_hex(),
        &make_entity_blob(ENTITY_TYPE_PERSON, T0 + 6, NEW_WORDS),
    );
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
