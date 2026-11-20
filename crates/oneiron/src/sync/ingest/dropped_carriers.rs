//! The peer carriers the ingest dropped for a record a refused privacy erase keeps (C6) or a
//! cooperative review restricts (REVIEW-9881 round 1).
//!
//! Such a record takes no change from a peer, as it takes none from a named write here (OF-470
//! C6). The window that brought a dropped carrier still carries it after the limit lifts, so a
//! later rematerialization would put it over the kept copy. The ingest records each carrier it
//! drops by its digest, and drops those exact bytes again whenever they come back. A device's
//! later edit is other bytes and lands once the limit has lifted. The row's erase forgets them.

use heed::{RoTxn, RwTxn};

use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const DROPPED: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESTRICTED_DROPPED_CARRIER);

const DIGEST_LEN: usize = 32;

fn digest(blob: &[u8]) -> [u8; DIGEST_LEN] {
    *blake3::hash(blob).as_bytes()
}

/// Whether the ingest dropped `blob`, a carrier of the row `id`, before.
///
/// # Errors
///
/// Storage failures.
pub(in crate::sync) fn carrier_dropped_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    let sum = digest(blob);
    Ok(DROPPED
        .get(store, txn, &HexId(*id))?
        .is_some_and(|held| held.chunks_exact(DIGEST_LEN).any(|held| held == sum)))
}

/// Whether the ingest drops `blob`, a peer's carrier of the row `id` that differs from the row
/// stored here: the ingest dropped these bytes before, or the record is use-limited or restricted
/// now, and then the carrier is recorded as dropped. The stored row's own bytes are never
/// dropped here: they take their own door or the replay skip.
///
/// # Errors
///
/// Storage failures.
pub(in crate::sync) fn drops_changed_carrier_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    if vault
        .store
        .port_entity_raw(wtxn, id)?
        .is_some_and(|local| *local == *blob)
    {
        return Ok(false);
    }
    if carrier_dropped_in_txn(&vault.store, wtxn, id, blob)? {
        return Ok(true);
    }
    if vault.store.use_restricted_in_txn(wtxn, id)?.is_none() {
        return Ok(false);
    }
    let mut held = DROPPED
        .get(&vault.store, wtxn, &HexId(*id))?
        .unwrap_or_default();
    held.extend_from_slice(&digest(blob));
    DROPPED.put(&vault.store, wtxn, &HexId(*id), &held)?;
    Ok(true)
}

/// Forgets the carriers dropped for the row `id`, in the transaction that erases it: each record
/// is a digest of bytes a device wrote for it, which could confirm a guess of them.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn forget_dropped_carriers_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    DROPPED.delete(store, wtxn, &HexId(*id))?;
    Ok(())
}
