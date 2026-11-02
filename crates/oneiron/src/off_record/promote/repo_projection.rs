//! What a promotion replays of a room's cached media vectors (FIX 7608
//! S3F, FIX 10407). A room's `MediaVector` op carries no stamp of the copy
//! it embedded, so a vector of a record whose media bytes a mark now covers
//! is not certified by its kind or text hash: it is left out of the
//! replay, and base embeds the record's copy on its next pass. A plan cut
//! before a mask change, an appended save's included, is judged by the
//! marks base holds now, not by whether the room's journal was pruned.
//! Every content op replays as it is; nothing is refused and no turn held.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::batch::BatchOp;
use crate::embed::repo_media_bytes;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_projection::index::RepoIndexMarks;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;

/// `ops`, a pinned plan's, as a promotion replays them: each `MediaVector`
/// op of a record whose media bytes (by the plan's own put, else the record
/// base holds) are a marked blob, or that is a marked blob's snapshot
/// record, left out. Marks are read only when the plan carries a media
/// vector; marks that cannot be read leave out every vector of a record
/// holding media, a refill rather than a loss.
///
/// # Errors
/// A store failure.
pub(super) fn projected_replay_ops<D: Borrow<BatchOp>>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ops: impl IntoIterator<Item = D>,
) -> Result<Vec<BatchOp>> {
    let ops: Vec<BatchOp> = ops.into_iter().map(|op| op.borrow().clone()).collect();
    if !ops
        .iter()
        .any(|op| matches!(op, BatchOp::MediaVector { .. }))
    {
        return Ok(ops);
    }
    let marks = match RepoIndexMarks::read_scoped_in_txn(vault, txn) {
        Ok(marks) if marks.is_empty() => return Ok(ops),
        Ok(marks) => Some(marks),
        Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => return Err(error),
        Err(error) => {
            tracing::warn!(error = %error, "a promotion's media vectors are embedded again");
            None
        }
    };
    let planned: BTreeMap<EntityId, &[u8]> = ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_ASSET,
                data,
                ..
            } => Some((*id, data.as_slice())),
            _ => None,
        })
        .collect();
    let mut stale = BTreeSet::new();
    for op in &ops {
        let BatchOp::MediaVector { id, .. } = op else {
            continue;
        };
        if marks
            .as_ref()
            .is_some_and(|marks| marks.source_of(id).is_some())
        {
            stale.insert(*id);
            continue;
        }
        // FIX 9949: an ASSET's bytes are the blob it holds by reference.
        let read = |blob: &EntityId| -> Result<Option<Vec<u8>>> {
            Ok(vault
                .store
                .port_entity_record(txn, blob)?
                .map(|blob| blob.body))
        };
        let bytes = match planned.get(id) {
            Some(data) => repo_media_bytes(data, read)?,
            None => match vault.store.port_entity_record(txn, id)? {
                Some(row) => repo_media_bytes(&row.body, read)?,
                None => None,
            },
        };
        let Some(bytes) = bytes else {
            continue;
        };
        if marks
            .as_ref()
            .is_none_or(|marks| marks.is_marked(blake3::hash(&bytes).as_bytes()))
        {
            stale.insert(*id);
        }
    }
    Ok(ops
        .into_iter()
        .filter(|op| !matches!(op, BatchOp::MediaVector { id, .. } if stale.contains(id)))
        .collect())
}
