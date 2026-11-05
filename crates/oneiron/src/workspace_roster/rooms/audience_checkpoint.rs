//! The content-free audience operation an old checkpoint must keep after
//! the edit's authored history is purged (FIX 14416).

use super::audience::{ThreadBinding, thread_binding};
use super::audience_events::{audience_event, event_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;

/// A strictly decoded edit, with its original binding and header times but
/// no editor or other body fields. A malformed or unrelated row has no
/// projection; its ordinary checkpoint placement is unchanged.
pub(crate) fn checkpoint_audience_operation(
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<(ThreadBinding, Vec<u8>)>> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_TURN {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let (Some(event), Some(binding)) = (
        audience_event(body).ok().flatten(),
        thread_binding(body).ok().flatten(),
    ) else {
        return Ok(None);
    };
    if event.root != binding.root || binding.root == *id || binding.audience.is_some() {
        return Ok(None);
    }
    let mut projected = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    projected.extend_from_slice(&event_body(&binding, &event.erased())?);
    Ok(Some((binding, projected)))
}

/// The original root, not another edit or a dangling binding. The restore
/// supplies an independently available entity row, never the projection.
pub(crate) fn checkpoint_audience_root_matches(raw: &[u8], binding: &ThreadBinding) -> bool {
    if !EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_TURN)
    {
        return false;
    }
    thread_binding(&raw[ENTITY_METADATA_HEADER_LEN..])
        .ok()
        .flatten()
        .is_some_and(|root| {
            root.root == binding.root
                && root.room == binding.room
                && root.anchor == binding.anchor
                && root.audience.is_some()
        })
}

/// The operation and its root in this exact capture view. Native deletion
/// truth is checked for both; a stored body alone does not make it live.
pub(crate) fn checkpoint_audience_operation_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<(ThreadBinding, Vec<u8>)>> {
    let Some((binding, projected)) = checkpoint_audience_operation(id, raw)? else {
        return Ok(None);
    };
    if crate::deletion::row_deletion_marked(dbs, txn, id, Some(raw))? {
        return Ok(None);
    }
    let Some(root) = dbs.entities().get(txn, binding.root.as_bytes())? else {
        return Ok(None);
    };
    if crate::deletion::row_deletion_marked(dbs, txn, &binding.root, Some(root))?
        || !checkpoint_audience_root_matches(root, &binding)
    {
        return Ok(None);
    }
    Ok(Some((binding, projected)))
}

/// Re-proves the new compartment's live owner in the mint's own writer,
/// including a first capture racing an erase before any instance existed.
pub(crate) fn checkpoint_audience_operation_live_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = dbs.entities().get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    Ok(checkpoint_audience_operation_in_txn(dbs, txn, id, raw)?.is_some())
}
