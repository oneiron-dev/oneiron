//! Core half of `store::linear_task_revision`: its store-layer items live in `oneiron_store::linear_task_revision` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::linear_task_revision::*;

use crate::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

pub(crate) const REVISIONS: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::LINEAR_TASK_REVISION);

pub(crate) const DIRTY: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::LINEAR_TASK_DIRTY);

/// Value: the task revision it stamps (u64be), the writer id16 and its actor class byte.
pub(crate) const WRITER: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::LINEAR_TASK_WRITER);

pub(crate) fn revision(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<u64> {
    Ok(REVISIONS.get(store, txn, &id)?.unwrap_or(0))
}

pub(crate) fn note_task_write(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<()> {
    if !task_body_has_typed_subkind(body)? {
        return Ok(());
    }
    let revision = revision(store, txn, id)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("task revision"))?;
    REVISIONS.put(store, txn, &id, &revision)?;
    DIRTY.put(store, txn, &id, &revision)?;
    WRITER.delete(store, txn, &id)?;
    Ok(())
}
