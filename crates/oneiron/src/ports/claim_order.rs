//! CLAIM origin-write ordering. All durable state uses the caller's writer.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{ManifestDbs, Store, StoreRead};
use crate::{EntityId, Error, Result, TimeRange};

pub(crate) const CLAIM_ROW_FLOOR: &[u8] = crate::side_table::PORTS_CLAIM_ROW_FLOOR.prefix;

/// The highest row version a carried CLAIM row may hold.
///
/// Row versions are counters: each local CLAIM write takes the vault-wide
/// floor plus one, and a carried version raises that floor. An honest vault
/// passes 2^48 only after 2^48 CLAIM writes, about nine years at a million
/// writes a second, so a carried version above it is a malformed row, never
/// a device ahead of this one. Admitted, it would lift the floor to where
/// floor + 1 overflows, and every later local CLAIM write would fail
/// (FIX SYNC-CLAIM-ROW-VERSION-FLOOR-POISON).
pub(crate) const CARRIED_CLAIM_ROW_VERSION_CEILING: u64 = 1 << 48;

/// Whether `header` keeps to [`CARRIED_CLAIM_ROW_VERSION_CEILING`]: every
/// row but a CLAIM does, and a CLAIM does at the ceiling or below.
pub(crate) fn fits_ceiling(header: &EntityMetadataHeader) -> bool {
    header.entity_type != ENTITY_TYPE_CLAIM
        || header.row_version <= CARRIED_CLAIM_ROW_VERSION_CEILING
}

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
/// A carried version past [`CARRIED_CLAIM_ROW_VERSION_CEILING`] is refused as
/// a malformed row and leaves the floor as it was. The sync ingest door
/// quarantines such a row first; this refusal holds for every other door
/// that carries a version.
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
    if carried.is_some_and(|version| version > CARRIED_CLAIM_ROW_VERSION_CEILING) {
        return Err(Error::CorruptedIndex("entity metadata"));
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
