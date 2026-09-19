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
        .filter(|row| {
            let Ok(body) = rmpv::decode::read_value(&mut std::io::Cursor::new(&row.body)) else {
                return true;
            };
            !body.as_map().is_some_and(|fields| {
                fields.iter().any(|(key, value)| {
                    key.as_str() == Some("stale") && value.as_bool() == Some(true)
                })
            })
        })
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
