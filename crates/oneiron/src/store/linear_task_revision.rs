//! The tracker mirror's revision rows for a typed TASK (`LINEAR_TASK_REVISION`,
//! `LINEAR_TASK_DIRTY`, `LINEAR_TASK_WRITER`) and the batch-door bump a TASK
//! put makes. The tracker mirror (`task_verb::linear_store`) reads and stamps
//! these rows; the store's put staging bumps them on a typed TASK write.
use crate::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

pub(crate) const TASK_VERB_BODY_SUBKIND: &str = "typed";

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

pub(crate) fn task_body_has_typed_subkind(body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("tasks.create.body")))?;
    if !cursor.is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )));
    }
    let Some(entries) = value.as_map() else {
        return Ok(false);
    };
    Ok(entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("subkind"))
        .count()
        == 1
        && entries
            .iter()
            .filter(|(key, value)| {
                key.as_str() == Some("subkind") && value.as_str() == Some(TASK_VERB_BODY_SUBKIND)
            })
            .count()
            == 1)
}
