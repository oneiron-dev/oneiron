//! Immutable task-authority fact row and edge deletion guards.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::write_envelope::task_body::{TaskRole, task_role_from_body_bytes};

/// Whether `id` is a stored authority fact.
pub(crate) fn is_task_authority_fact_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("task authority fact guard header"))?;
    Ok(header.entity_type == ENTITY_TYPE_TASK
        && raw.len() > ENTITY_METADATA_HEADER_LEN
        && matches!(
            task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]),
            Ok(TaskRole::AuthorityFact)
        ))
}

/// A fact is read through its `fact --ScopedTo--> task` link, so removing
/// the link, or the fact, would read as a requirement never made or a party
/// never named, and let the next fact stand as the first. No door removes
/// either; a hard delete of the subject takes the link with its row.
pub(crate) fn reject_fact_link_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
) -> Result<()> {
    if kind == EdgeKind::ScopedTo && is_task_authority_fact_in(store, txn, src)? {
        return Err(fact_removal_refused());
    }
    Ok(())
}

/// [`reject_fact_link_delete`] for the fact row itself.
pub(crate) fn reject_fact_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if is_task_authority_fact_in(store, txn, id)? {
        return Err(fact_removal_refused());
    }
    Ok(())
}

pub(crate) fn fact_removal_refused() -> Error {
    Error::Record(RecordError::InvalidTaskBody(
        "task authority facts are immutable",
    ))
}
