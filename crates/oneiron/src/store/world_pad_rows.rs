//! The world-key pad rows' store facts (KS-5): a world whose keys were
//! destroyed or that was soft-deleted here, a pad row hard-erased here, and
//! the world a stored pad row names. The world-key custody (`world_keys`)
//! writes the destroyed mark; the deletion and pad custody paths read these.

use heed::RoTxn;
use oneiron_store::world_pad_codec::{key_of_id, pad_row_id, pad_world_in_body};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::key_material::WorldKeyDestruction;
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_WORLD, ENTITY_TYPE_WORLD_KEY_PAD};
use crate::side_table::{self, HexId, Named, Raw, SideTable};
use crate::store::Store;

pub(crate) const DESTROYED: SideTable<HexId, WorldKeyDestruction, Named> =
    SideTable::new(&side_table::WORLD_KEY_DESTROYED);
/// When a world was soft-deleted here, in vault seconds.
pub(crate) const DELETED: SideTable<HexId, u64, Raw> =
    SideTable::new(&side_table::WORLD_KEY_DELETED);

/// Whether `world`'s keys were destroyed here, or the world was erased here: a
/// hard-delete marker. A soft delete keeps the keys, so a soft-deleted world
/// still takes its own pads. Absence of the WORLD row alone is not
/// destruction: a first sync can bring a pad before its world.
pub(crate) fn world_keys_destroyed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<bool> {
    let id = HexId(world);
    Ok(DESTROYED.contains(store, txn, &id)?
        || store.port_deletion_marked(txn, DeletionMarker::HardDelete, &world)?)
}

/// Records when `world` was soft-deleted, in the delete's own transaction, so a
/// pin change keeps its keys restorable for [`DELETED_WORLD_KEEP_SECS`]. A row
/// that is not a WORLD is skipped, and the first record stands.
pub(crate) fn note_world_deleted_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    world: EntityId,
    deleted_at: u64,
) -> Result<()> {
    let is_world = store
        .port_entity_with_raw(wtxn, &world, |raw| {
            Ok(EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD))
        })?
        .unwrap_or(false);
    let key = HexId(world);
    if is_world && !DELETED.contains(store, wtxn, &key)? {
        DELETED.put(store, wtxn, &key, &deleted_at)?;
    }
    Ok(())
}

/// The world whose key a pad row `raw` splits: `None` for a row that is not
/// a pad, an error for a pad whose body does not decode. Sync reads it to place
/// a live pad in its world's windows and to keep a destroyed world's late pad
/// out of every window.
pub(crate) fn pad_body_world(raw: &[u8]) -> Option<Result<EntityId>> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_WORLD_KEY_PAD {
        return None;
    }
    Some(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("world key pad body"))
            .and_then(pad_world_in_body),
    )
}

/// Whether the pad row of the key a custody `item` (its full id) names was
/// hard-erased here: the custody finisher's check for a retirement
/// [`stage_pad_row_erase_in_txn`] staged.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn pad_row_erased_in_txn(store: &Store, txn: &RoTxn<'_>, item: &[u8]) -> Result<bool> {
    let Some(key) = key_of_id(item) else {
        return Ok(false);
    };
    store.port_deletion_marked(txn, DeletionMarker::HardDelete, &pad_row_id(&key)?)
}
