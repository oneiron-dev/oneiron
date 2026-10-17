//! Integrity reads compose ports without opening a transaction.
use super::{EntityStore, TombstoneStore};
use crate::{EntityId, error::Result};
pub fn safe_read_text<P: EntityStore + TombstoneStore>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let row = ports.port_entity_get(txn, id)?;
    if ports.port_tombstone_is_deleted(txn, id)? {
        return Ok(None);
    }
    Ok(row
        .filter(|row| !body_is_stale(&row.body))
        .map(|row| row.body))
}
pub fn safe_read_asset_text<P: EntityStore + TombstoneStore>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
    derived_hash: &[u8; 32],
    source_hash: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if derived_hash != source_hash {
        return Ok(None);
    }
    safe_read_text(ports, txn, id)
}

/// Whether `id`'s own words are withdrawn in this snapshot: deleted, marked
/// stale, covered by a pending source walk (I1, I2), or kept only under a
/// legal-hold use limit after a refused privacy erasure (OF-470 C6). A door
/// that returns a stored body refuses such a row; maintenance and
/// capture-before-purge read the raw ports instead.
pub(crate) fn withdrawn_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        super::TombstoneStoreRead::port_deletion_state(store, txn, id)?.deleted
            || super::stale_in_txn(store, txn, id)?
            || crate::store::legal_hold::use_limit_in_txn(store, txn, id)?.is_some(),
    )
}

pub(crate) fn body_is_stale(bytes: &[u8]) -> bool {
    let Ok(body) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return false;
    };
    body.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("stale") && value.as_bool() == Some(true))
    })
}
