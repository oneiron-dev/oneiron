//! #1465 R2 checks on the tombstones a hard erase stages for the carriers it pierced.

use crate::Vault;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::deletion::DeleteReason;
use crate::deletion::erase::PiercedCarrier;
use crate::deletion::tombstone::{
    PENDING_TOMBSTONE, PendingTombstoneKey, TombstoneReason, TombstoneValueV2,
    window_label_from_timestamp,
};
use crate::deletion::topology_delete_intent::{
    TopologyDeletePhase, reserve_topology_delete_in_txn, topology_delete_reservation_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::write_envelope::WriteActor;

const SHARED: &[u8] = b"bytes two artifacts hold";

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

fn another_request() -> TombstoneValueV2 {
    TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at: 50,
        request_id: [0x0B; 16],
    }
}

/// Two artifacts holding `SHARED`; returns them and the second one's reference.
fn shared(vault: &Vault) -> Result<(EntityId, EntityId, EntityId)> {
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at(10), 10, b"uploader")?;
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let mut ids = Vec::new();
    for learned in [11, 12] {
        let id = EntityId::now();
        vault.put_blob_artifact(
            &id,
            &BlobArtifactBody::new("shared.bin", "application/octet-stream"),
            at(10),
            10,
        )?;
        vault.append_blob_artifact_version(
            &id,
            SHARED,
            &BlobVersionProvenance::UserUpload,
            actor,
            at(learned),
            learned,
        )?;
        ids.push(id);
    }
    let reference = vault
        .blob_artifact_head(&ids[1])?
        .expect("the other artifact's head")
        .claim_id;
    Ok((ids[0], ids[1], reference))
}

/// Bug repro (#1465 R2, Sol F6 and Astra F8): another request's hard delete of a pierced
/// reference that is only Prepared has published nothing and may never publish. The erase's own
/// tombstone for that reference takes the reservation over and publishes, instead of leaving the
/// reference with no tombstone at all.
#[test]
fn a_prepared_competing_request_does_not_hold_back_a_pierced_tombstone() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (erased, _other, reference) = shared(&vault)?;
    let competing = another_request();
    vault.with_write_txn_grouped(|txn| {
        reserve_topology_delete_in_txn(
            &vault.store,
            txn,
            &reference,
            &competing,
            12,
            TopologyDeletePhase::Prepared,
        )
    })?;
    vault.delete_entity_with_reason(&erased, DeleteReason::GdprDelete)?;
    let txn = vault.store.env.read_txn()?;
    assert!(
        topology_delete_reservation_in_txn(&vault.store, &txn, &reference)?
            .is_none_or(|intent| intent.request_id != competing.request_id),
        "a merely Prepared request kept the pierced reference's reservation"
    );
    Ok(())
}

/// Bug repro (#1465 R2, Sol F8): once the erase's transaction tore a carrier, publishing its
/// tombstone is settled. A legal hold placed after the tear refuses nothing there, and the
/// tombstone still reaches the window.
#[test]
fn a_pierced_tombstone_publishes_after_its_tear_whatever_holds_since() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let carrier = EntityId::now();
    let window_label = window_label_from_timestamp(13);
    let value = another_request();
    let staged = vault.with_write_txn_grouped(|txn| {
        vault.stage_pierced_tombstones_in_txn(
            txn,
            vec![PiercedCarrier {
                id: carrier,
                learned_at: 13,
                window_label: window_label.clone(),
            }],
            &value,
        )
    })?;
    assert_eq!(staged.len(), 1);
    vault.set_gate_decision_partition_hold(Some(*carrier.as_bytes()), true)?;
    vault.publish_pierced_tombstones(&staged, &value)?;
    let doc = crate::sync::window::load_window_from_state(
        &vault,
        "local",
        &crate::sync::WindowKey::new(&window_label),
    )?;
    assert!(
        doc.get_map("tombstones").get(&carrier.to_hex()).is_some(),
        "the pierced carrier's tombstone never reached its window"
    );
    let txn = vault.store.env.read_txn()?;
    assert!(
        PENDING_TOMBSTONE
            .get_bytes(
                &vault.store,
                &txn,
                &PendingTombstoneKey {
                    window: window_label,
                    id: carrier,
                },
            )?
            .is_none()
    );
    Ok(())
}
