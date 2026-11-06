//! CLAIM origin-write ordering. All durable state uses the caller's writer.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{ManifestDbs, Store, StoreRead};
use crate::{EntityId, Error, Result, TimeRange};

pub(crate) const CLAIM_ROW_FLOOR: &[u8] = crate::side_table::PORTS_CLAIM_ROW_FLOOR.prefix;

pub(crate) fn decode_floor(bytes: Option<&[u8]>) -> Result<u64> {
    bytes.map_or(Ok(0), |bytes| {
        bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::CorruptedIndex("claim row floor"))
    })
}

pub(crate) fn floor_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    let bytes = store.vault_meta().get(txn, CLAIM_ROW_FLOOR)?;
    decode_floor(bytes.as_deref())
}

pub(crate) fn observe_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, version: u64) -> Result<()> {
    if version > floor_in_txn(store, txn)? {
        store
            .vault_meta()
            .put(txn, CLAIM_ROW_FLOOR, &version.to_be_bytes())?;
    }
    Ok(())
}

/// Final, admitted bytes determine whether a local put is a logical rewrite.
/// Carried metadata is never restamped, even when the current floor is later.
pub(crate) fn for_put_in_txn(
    target: StoreRead<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    metadata: (u8, TimeRange, u64),
    data: &[u8],
    carried: Option<u64>,
) -> Result<u64> {
    let (entity_type, occurred, learned_at) = metadata;
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(carried.unwrap_or(0));
    }
    let (previous, unchanged) = match target.port_entity_raw_wiped(txn, id)? {
        Some(raw) => {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            (
                header.row_version,
                header.entity_type == entity_type
                    && header.occurred_start == occurred.start
                    && header.occurred_end == occurred.end
                    && header.learned_at == learned_at
                    && &raw[ENTITY_METADATA_HEADER_LEN..] == data,
            )
        }
        None => (0, false),
    };
    let base = target.base();
    let floor = floor_in_txn(base, txn)?
        .max(previous)
        .max(carried.unwrap_or(0));
    let version = match carried {
        Some(version) => version,
        None if unchanged => previous,
        None => floor
            .checked_add(1)
            .ok_or(Error::IndexOverflow("claim row version"))?,
    };
    observe_in_txn(base, txn, floor.max(version))?;
    Ok(version)
}
