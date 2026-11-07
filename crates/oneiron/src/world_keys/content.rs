//! The sealing mirrors of private worlds' windows (OF-570 (d), FIX 922): a
//! reader's own Loro document per window of a world it may read, packed with
//! every row of the window. The world's section of the sealed cloud bundle
//! carries each mirror whole (`content_window`, `bundle`). Erasing the world
//! purges its mirrors on every replica that applies the erase; deleting it
//! purges nothing.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// A reader's own Loro document per sealed window. Key: hex32 (world) ":"
/// window label.
pub(super) const MIRROR: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_MIRROR);

/// How many actor erases rewrote the mirrors here (FIX 17210), under
/// [`MIRROR_ERASES_KEY`]: a seal or a take checks it again before it writes.
pub(super) const MIRROR_ERASES: SideTable<String, u64, Named> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_MIRROR_ERASES);
/// The one key of [`MIRROR_ERASES`].
pub(super) const MIRROR_ERASES_KEY: &str = "count";

/// How many actor erases rewrote the mirrors here, read in `txn`.
pub(super) fn mirror_erases_in(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(MIRROR_ERASES
        .get(store, txn, &MIRROR_ERASES_KEY.to_owned())?
        .unwrap_or(0))
}

/// Which version of each window's mirror last landed here in full
/// (`content_landed`, FIX 5506). Key: hex32 (world) ":" window label.
pub(super) const LANDED: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_MIRROR_LANDED);

/// Purges every mirror of `world`, and every mark of what landed from one,
/// in the caller's write transaction: the erase's share here, and a world
/// placed on one other machine leaving this one (FIX 14534).
pub(crate) fn purge_world_mirrors_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    world: EntityId,
) -> Result<()> {
    let prefix = format!("{}:", world.to_hex());
    for key in MIRROR.scan_keys(store, wtxn, prefix.as_bytes())? {
        MIRROR.delete(store, wtxn, &key)?;
    }
    for key in LANDED.scan_keys(store, wtxn, prefix.as_bytes())? {
        LANDED.delete(store, wtxn, &key)?;
    }
    Ok(())
}
