//! A local hard erase of one world key pad row alone (KS-5, FIX 7192): its
//! key's custody entry retires, as a peer's hard tombstone of the row
//! retires it, never another pad of its world.
//!
//! The delete door writes the row's hard-delete marker in its erasing
//! transaction before the purge, which stages the retirement
//! (`deletion::erase`). A batch delete wrote none: here it stages the row's
//! marker and pending tombstone with the retirement, in the batch's own
//! transaction, so the custody finisher reads the marker after the commit
//! and every replica erases the row too. A world erase stays the world's.

use heed::RwTxn;
use zeroize::Zeroizing;

use super::pad_custody::{decode_pad_body, pad_row_body, stage_pad_row_erase_in_txn};
use super::pads::pad_window;
use crate::batch::EntityMetadataHeader;
use crate::deletion::{TombstoneReason, TombstoneValueV2, stage_engine_row_hard_erasure_at_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::store::Store;

/// A batch delete of the row `id`, before it is torn, when it is a pad row:
/// its key's custody retirement staged, and its hard-delete marker and
/// pending tombstone staged in its world's window of the month it was
/// learned (a header-only shell's, where its deletion went), published once
/// the batch commits (FIX 3334). The tombstone names the row as its own
/// request, as a batch delete has none. Any other row stages nothing.
///
/// # Errors
///
/// Custody and storage faults.
pub(crate) fn erase_batch_pad_row_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    deleted_at: u64,
) -> Result<()> {
    let Some(raw) = store.port_entity_raw(wtxn, id)?.map(Zeroizing::new) else {
        return Ok(());
    };
    let Some(body) = pad_row_body(&raw) else {
        return Ok(());
    };
    let world = decode_pad_body(body).ok().map(|body| body.key().world);
    let window = match (world, EntityMetadataHeader::parse(&raw)) {
        (Some(world), Some(header)) => pad_window(world, header.learned_at),
        _ => crate::deletion::deletion_window_for_row(store, wtxn, id, &raw)?,
    };
    stage_pad_row_erase_in_txn(store, wtxn, id)?;
    let tombstone = TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at,
        request_id: *id.as_bytes(),
    };
    stage_engine_row_hard_erasure_at_in_txn(store, wtxn, id, window.clone(), &tombstone)?;
    crate::batch::queue_pad_tombstone_window(store, wtxn, window);
    Ok(())
}
