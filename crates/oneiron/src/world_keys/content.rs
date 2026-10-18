//! The sealing mirrors of private worlds' windows (OF-570 (d), FIX 922): a
//! reader's own Loro document per window of a world it may read, packed with
//! every row of the window. The world's section of the sealed cloud bundle
//! carries each mirror whole (`content_window`, `bundle`). Erasing the world
//! purges its mirrors on every replica that applies the erase; deleting it
//! purges nothing.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// A reader's own Loro document per sealed window. Key: hex32 (world) ":"
/// window label.
pub(super) const MIRROR: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_MIRROR);

/// Purges every mirror of `world`, in the caller's write transaction: the
/// erase's share here.
pub(super) fn purge_world_mirrors_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    world: EntityId,
) -> Result<()> {
    let prefix = format!("{}:", world.to_hex());
    for key in MIRROR.scan_keys(store, wtxn, prefix.as_bytes())? {
        MIRROR.delete(store, wtxn, &key)?;
    }
    Ok(())
}
