//! Restore and activation reconciliation for native observation captures.
//! An omitted claim/version is not an erase. This never releases bytes,
//! erases a claim, changes a hold, or discards a LIVE release obligation.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::PINS;

/// Drops only captures the restored content no longer holds. A live
/// unfinished release outranks an older capture of its original owner;
/// otherwise the actual claim and exact version must stand. Retired body
/// instances cannot resurrect through metadata; a standing version keeps
/// its native capture so later teardown can still release that version.
/// Observation bodies and LIVE releases stay untouched.
pub(crate) fn prune_line_chat_archive_pins_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    for (claim, pin) in PINS.scan(store, txn)? {
        let raw = store.port_entity_raw(txn, &claim)?;
        let retained = match raw.as_deref() {
            Some(raw) if raw.len() > ENTITY_METADATA_HEADER_LEN && raw[0] == ENTITY_TYPE_CLAIM => {
                !crate::deletion::row_deletion_marked(store, txn, &claim, Some(raw))?
            }
            _ => false,
        };
        if !retained
            || super::lifetime::release_pending_in_txn(store, txn, &claim)?
            || !crate::blob_artifact::archive_version_stands_in_txn(
                store,
                txn,
                &pin.artifact_id,
                pin.version,
                &pin.content_hash,
                &pin.version_claim,
            )?
        {
            PINS.delete(store, txn, &claim)?;
        }
    }
    Ok(())
}
