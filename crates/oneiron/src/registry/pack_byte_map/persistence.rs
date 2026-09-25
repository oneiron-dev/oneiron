//! Content-addressed ASSET custody plus a vault-local install-authority head pin.

use super::types::{PackByteMapSnapshot, invalid};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::{RoTxn, RwTxn};

/// Local command state only. Never import or sync this key as authority.
pub(super) const HEAD_KEY: &[u8] = b"pack_byte_map:local_head:v1";
const CARRIER_DOMAIN: &[u8] = b"oneiron:pack-byte-map-carrier:v1";

pub(super) fn carrier_id(hash: &[u8; 32]) -> Result<EntityId> {
    entity_id_from_hash_material(CARRIER_DOMAIN, &[hash])
}

pub(super) fn read(store: &Store, txn: &RoTxn<'_>) -> Result<Option<PackByteMapSnapshot>> {
    let Some(pin) = store.vault_meta.get(txn, HEAD_KEY)? else {
        return Ok(None);
    };
    let hash: [u8; 32] = pin
        .as_ref()
        .try_into()
        .map_err(|_| invalid("invalid local pack map head pin"))?;
    let id = carrier_id(&hash)?;
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(|| invalid("local pack map carrier missing"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| invalid("invalid pack map carrier header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET
        || !crate::vault::live_entity_row_in_txn(store, txn, &id)?.is_live()
    {
        return Err(invalid("local pack map carrier is not a live ASSET"));
    }
    let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
    if blake3::hash(bytes).as_bytes() != &hash {
        return Err(invalid("local pack map carrier hash drift"));
    }
    let map: PackByteMapSnapshot =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid pack map carrier body"))?;
    map.validate()?;
    Ok(Some(map))
}

pub(super) fn persist(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    map: &mut PackByteMapSnapshot,
) -> Result<()> {
    map.revision = map
        .revision
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("pack map revision"))?;
    map.validate()?;
    let bytes = serde_json::to_vec(map).map_err(|_| invalid("pack map encoding failed"))?;
    let hash = *blake3::hash(&bytes).as_bytes();
    let id = carrier_id(&hash)?;
    if let Some(existing) = vault.store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&existing)
            .ok_or_else(|| invalid("invalid occupied pack carrier id"))?;
        if header.entity_type != ENTITY_TYPE_ASSET
            || existing[ENTITY_METADATA_HEADER_LEN..] != bytes
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
        {
            return Err(invalid("pack map carrier id collision"));
        }
    } else {
        let now = crate::unix_seconds_now();
        vault
            .batch_in()
            .put(
                &id,
                ENTITY_TYPE_ASSET,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &bytes,
            )
            .apply(txn)?;
    }
    // Pin publication and the ordinary ASSET write commit atomically. The
    // carrier alone can sync; the local install-authority pin never does.
    vault.store.vault_meta.put(txn, HEAD_KEY, &hash)?;
    Ok(())
}
