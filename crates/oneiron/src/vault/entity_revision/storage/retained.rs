//! The revisions a row retains, read for a TURN's text revision search.

use super::{FRONTIER, raw_for_revision, reference, state};
use crate::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::vault::entity_revision::RevisionRef;
use heed::RoTxn;

/// Every revision `id`'s row can be read at whose first byte is `first`: of
/// its current row, its live and indexed frontiers, and each retained one.
/// The retained ones are read from that byte's key range alone.
pub(in crate::vault::entity_revision) fn row_revisions_starting_with_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    first: u8,
) -> Result<Vec<RevisionRef>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(Vec::new());
    };
    let mut revisions = vec![reference(id, &raw)];
    if let Some(current) = state(store, txn, id)? {
        revisions.extend([current.live, current.indexed]);
    }
    let mut prefix = id.as_bytes().to_vec();
    prefix.push(first);
    revisions.extend(
        FRONTIER
            .scan_keys(store, txn, &prefix)?
            .into_iter()
            .map(|(_, revision)| RevisionRef(revision)),
    );
    revisions.retain(|revision| revision.0[0] == first);
    revisions.sort_unstable();
    revisions.dedup();
    Ok(revisions)
}

/// `id`'s row as stored, then as it stood at every revision its document
/// retains.
pub(in crate::vault::entity_revision) fn retained_rows_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<Vec<u8>>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(Vec::new());
    };
    let mut rows = vec![raw_for_revision(store, txn, id, &raw, None)?];
    if !state(store, txn, id)?.is_some_and(|current| current.has_doc) {
        return Ok(rows);
    }
    for row in FRONTIER.iter_from(store, txn, id.as_bytes())? {
        let ((_, revision), _) = row?;
        rows.push(raw_for_revision(
            store,
            txn,
            id,
            &raw,
            Some(RevisionRef(revision)),
        )?);
    }
    Ok(rows)
}

/// The row revisions `id`'s entity document took over at its birth, each
/// with the frontier it names there: a retained revision whose key is not
/// the reference of its own frontier, as `capture_entity_document` keeps
/// the row's live and indexed ones. A native document revision is that
/// reference, and is not one.
pub(in crate::vault::entity_revision) fn row_aliases_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<(RevisionRef, Vec<u8>)>> {
    let mut aliases = Vec::new();
    for row in FRONTIER.iter_from(store, txn, id.as_bytes())? {
        let ((_, revision), frontier) = row?;
        if reference(id, &frontier).0 != revision {
            aliases.push((RevisionRef(revision), frontier));
        }
    }
    Ok(aliases)
}
