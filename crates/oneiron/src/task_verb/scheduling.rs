//! Live TASK dependency and symbol readiness at every attempt-claim door.
use super::TaskTerminalDisposition;
use super::wire_decode::{decode_task_verb_body, task_body_has_typed_subkind};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, edge::EdgeKind};

pub(crate) fn terminal_success_in_store(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &task)? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("task header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_TASK {
        return Ok(false);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if !task_body_has_typed_subkind(body)? {
        return Ok(false);
    }
    Ok(decode_task_verb_body(body)?
        .terminal()
        .is_some_and(|terminal| terminal.disposition == TaskTerminalDisposition::Completed))
}

pub(crate) fn task_dispatch_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task_ref: Option<&str>,
    now: u64,
) -> Result<bool> {
    let Some(task) = task_ref.and_then(|id| EntityId::from_hex(id).ok()) else {
        return Ok(true);
    };
    for row in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        &task,
        crate::ports::EdgeDirection::Out,
        Some(EdgeKind::BlockedBy),
        None,
    )? {
        let blocker = row?.target;
        if !terminal_success_in_store(store, txn, blocker)? {
            return Ok(false);
        }
    }
    super::symbols_ready(store, txn, task, now)
}

pub(crate) fn acquire_task_symbols(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task_ref: Option<&str>,
    now: u64,
) -> Result<()> {
    if let Some(task) = task_ref.and_then(|id| EntityId::from_hex(id).ok()) {
        super::acquire_symbols(store, txn, task, now)?;
    }
    Ok(())
}
