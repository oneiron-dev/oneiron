//! The retained states of an entity's document, read as record bodies.

use super::super::EntityDoc;
use super::super::document::decode_frontier;
use super::{TextField, body_with_document, has_record_head, head, load};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use heed::RoTxn;

/// One state of an entity's document, as [`record_body_history_in_txn`]
/// lists it.
pub(crate) struct RetainedBody {
    /// The frontier [`crate::entity_doc::source_frontier_in_txn`] names the
    /// state by.
    pub(crate) frontier: Vec<u8>,
    /// The record body there ([`super::resolve_record_body`] at that state).
    pub(crate) body: Vec<u8>,
}

/// `entity`'s record body at the states its document's retained history
/// names, newest first: the current one, then for each of the newest
/// `limit` changes the state it left and the state it was made on (its
/// dependencies, which name a merged state the next edit followed). `None`
/// for an unmigrated row. A state of concurrent heads no later change was
/// made on, or whose history was purged, is not listed.
pub(crate) fn record_body_history_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    body: &[u8],
    limit: usize,
) -> Result<Option<Vec<RetainedBody>>> {
    if !has_record_head(store, txn, entity)? {
        return Ok(None);
    }
    let h = head(store, txn, entity)?;
    let doc = load(store, txn, &h)?;
    let current = doc.doc.oplog_frontiers();
    let mut frontiers = vec![current.encode()];
    let mut visited = 0;
    doc.doc
        .travel_change_ancestors(&current.to_vec(), &mut |meta| {
            let last = meta.id.inc(i32::try_from(meta.len).unwrap_or(i32::MAX) - 1);
            frontiers.push(loro::Frontiers::from_id(last).encode());
            if !meta.deps.is_empty() {
                frontiers.push(meta.deps.encode());
            }
            visited += 1;
            if visited < limit {
                std::ops::ControlFlow::Continue(())
            } else {
                std::ops::ControlFlow::Break(())
            }
        })
        .map_err(|_| Error::CorruptedIndex("document change history"))?;
    let live = doc.frontier();
    // One private scratch copy, checked out per ancestor frontier, instead of
    // an export and import per state. It stays `None` until the first
    // ancestor needs it, and for a shallow document, whose fork keeps its own
    // retained-state check.
    let mut scratch: Option<EntityDoc> = None;
    let mut states: Vec<RetainedBody> = Vec::with_capacity(frontiers.len());
    for frontier in frontiers {
        let mut pin = h.incarnation.clone().into_bytes();
        pin.extend_from_slice(&frontier);
        if states.iter().any(|state| state.frontier == pin) {
            continue;
        }
        if frontier == live {
            states.push(RetainedBody {
                frontier: pin,
                body: body_with_document(&h.field, body, &doc)?,
            });
            continue;
        }
        if !doc.doc.is_shallow()
            && let Some(read) = read_with_scratch(&doc, &h.field, body, &frontier, &mut scratch)
        {
            states.push(RetainedBody {
                frontier: pin,
                body: read,
            });
            continue;
        }
        let Ok(version) = doc.fork(&frontier) else {
            continue;
        };
        states.push(RetainedBody {
            frontier: pin,
            body: body_with_document(&h.field, body, &version)?,
        });
    }
    Ok(Some(states))
}

/// The body at `frontier`, read by checking out one private scratch copy of
/// `doc`. `None` where checkout cannot name the same state a fork would, so
/// the caller falls back to the fork.
fn read_with_scratch(
    doc: &EntityDoc,
    field: &TextField,
    body: &[u8],
    frontier: &[u8],
    scratch: &mut Option<EntityDoc>,
) -> Option<Vec<u8>> {
    let at = decode_frontier(frontier).ok()?;
    if scratch.is_none() {
        *scratch = Some(EntityDoc::from_loro(doc.doc.fork()).ok()?);
    }
    let scratch = scratch.as_ref()?;
    scratch.doc.checkout(&at).ok()?;
    body_with_document(field, body, scratch).ok()
}
