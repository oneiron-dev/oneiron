//! One ingest entry per replicated container: every entities-map value and every tombstone
//! takes the same ladder whether forward rematerialization or Observer B carries it.
//!
//! The passes keep only what differs between them: forward rematerialization opens a write
//! transaction per entity and keeps the window's marker ledger; Observer B batches a delta
//! under one transaction and flags `rm:` markers when that transaction dies. Endpoint
//! hydration and the recovery preflight call the same entity ladder.

mod birth_watch;
mod claim_source_tombstones;
mod delivery;
mod dependent_sources;
mod dropped_carriers;
mod entity;
mod member_sender;
mod message_writer;
// A refusal notice raised on several machines keeps the marks of each copy.
mod notification_marks;
mod order;
mod own_device;
mod peer_import;
// FIX 3656: a guest's carried birth placements, landed beside their rows.
mod placement;
mod promotion;
mod room_pins;
mod task_pairs;
mod tombstone;

pub(in crate::sync) use self::birth_watch::{note_born, watch_births, watches};
pub(in crate::sync) use self::claim_source_tombstones::proven_carrier_deletions_in_txn;
pub(in crate::sync) use self::delivery::{
    Delivery, ShellDelivery, delivered_rows, delivered_tombstones, note_delivered_in_txn,
    payload_rows, with_delivery,
};

pub(crate) use self::dropped_carriers::forget_dropped_carriers_in_txn;
pub(in crate::sync) use self::dropped_carriers::{
    carrier_dropped_in_txn, drops_changed_carrier_in_txn,
};
#[cfg(test)]
pub(in crate::sync) use self::entity::ingest_entity_in_savepoint;
pub(in crate::sync) use self::entity::{
    EntityStep, IngestCtx, RefusalRetry, Residence, ingest_entity_in_txn, land_source_audience_in,
    waits_for_sibling_row,
};
pub(in crate::sync) use self::member_sender::{member_body_refused, with_member_sender};
pub(in crate::sync) use self::message_writer::{
    MESSAGE_WRITER_MAP, admit_writer_proof_carrier, admit_writer_proof_map, copy_writer_proofs,
    forget_written_rows, forget_written_rows_in_txn, publish_writer_proof,
};
pub(crate) use self::message_writer::{forget_message_writer_in_txn, note_message_put_in_txn};
pub(in crate::sync) use self::order::{authority_parent_order, is_authority_row};
pub(crate) use self::own_device::VerifiedOwnDeviceLane;
pub(in crate::sync) use self::own_device::with_own_device_import;
pub use self::own_device::with_own_device_push;
pub(crate) use self::peer_import::forget_stale_peer_origins;
pub(in crate::sync) use self::peer_import::{
    PEER_ORIGIN_MAP, admit_peer_origin_carrier, admit_peer_origin_map, admitted_peer_rows,
    carried_origin_in_txn, carry_peer_rows, copy_peer_origins, forget_peer_origin,
    forget_peer_rows, forget_peer_rows_in_txn, peer_row_in_txn, record_peer_rows,
};
pub(in crate::sync) use self::placement::{AdmittedPlacements, with_placements};
pub(in crate::sync) use self::promotion::{
    first_promotion_open, with_first_promotion_open, with_promotion,
};
pub(in crate::sync) use self::task_pairs::{TaskComponents, ingest_rows_in_savepoint};
pub(in crate::sync) use self::tombstone::{
    TombstoneStep, classify_tombstone, classify_tombstone_in_txn,
};

#[cfg(oneiron_test_support)]
pub(crate) use self::peer_import::asset_digest_for_test;

/// Lands the carried entities-map value `blob` of the row `id`, in the window `window_key`,
/// through the one entity ladder in a write of its own, as a window's sync carries it. An error
/// where the ladder does not materialize the row.
///
/// # Errors
///
/// The ladder's refusal or skip of the row; storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn ingest_carried_entity_for_test(
    vault: &crate::Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
    blob: &[u8],
) -> crate::error::Result<()> {
    let doc = loro::LoroDoc::new();
    let tombstones = crate::sync::loro_support::TombstoneIndex::build(&doc.get_map("tombstones"));
    let ctx = IngestCtx::new(
        vault,
        window_key,
        crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        &tombstones,
    );
    vault.with_write_txn(|wtxn| {
        match entity::ingest_entity_in_savepoint(&ctx, wtxn, &id.to_hex(), Some(blob))? {
            EntityStep::Materialized(_) => Ok(()),
            _ => Err(crate::error::Error::InvariantViolation(
                "the carried row did not materialize",
            )),
        }
    })
}
