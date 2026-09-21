//! Close the legacy ChildOf-only append door after DAG adoption.
use super::graph::{MIGRATED, invalid, key};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::store::Store;
use crate::{
    EntityId,
    registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN},
};
fn permit_key(record: &EntityId) -> Vec<u8> {
    key(b"conversation_dag:append_in_txn:v1:", record)
}
pub(super) fn permit(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    conversation: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &permit_key(record), conversation.as_bytes())?;
    Ok(())
}
pub(super) fn finish(store: &Store, txn: &mut heed::RwTxn<'_>, record: &EntityId) -> Result<()> {
    store.vault_meta.delete(txn, &permit_key(record))?;
    Ok(())
}
/// Reached by both public edge put flavors. Received edge materialization is
/// not a local append and retains the existing replay-validation path.
pub(crate) fn validate_local_membership(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    kind: EdgeKind,
    conversation: EntityId,
) -> Result<()> {
    if kind != EdgeKind::ChildOf {
        return Ok(());
    }
    let is_kind = |id: &EntityId, kind| -> Result<bool> {
        Ok(store
            .port_entity_record(txn, id)?
            .map(|row| row.encode())
            .is_some_and(|raw| raw.first() == Some(&kind)))
    };
    if !is_kind(&record, ENTITY_TYPE_TURN)? || !is_kind(&conversation, ENTITY_TYPE_CONVERSATION)? {
        return Ok(());
    }
    if crate::conversation::ownership::owner_in(store, txn, conversation)?
        != Some(crate::conversation::ownership::Owner::Dag)
    {
        return Ok(());
    }
    let marker = store.vault_meta.get(txn, &key(MIGRATED, &conversation))?;
    let Some(marker) = marker else {
        return Ok(());
    };
    if marker.as_ref() != [1] {
        return Err(Error::CorruptedIndex("conversation migration marker"));
    }
    if store
        .port_edge_get(txn, &record, kind, &conversation)?
        .is_some()
    {
        return Ok(());
    }
    if store
        .vault_meta
        .get(txn, &permit_key(&record))?
        .is_some_and(|bytes| bytes.as_ref() == conversation.as_bytes())
    {
        return Ok(());
    }
    Err(invalid(
        "conversation adopted DAG; append through append_dag_record",
    ))
}
