//! A thread audience edit stays while its thread's root lives (FIX 5639).
//! Engine ruling 2026-10-19: "Erasing a remove edit must keep the edit's op
//! and order as a content-free tombstone, so the removed person stays out."
//!
//! The fold finds a root's edits through their live TURNs and their `About`
//! edges to the root ([`super::audience_events`]), so a delete that drops an
//! edit's TURN, or hides it, or tears its `About` edge, undoes the edit: a
//! removed person reads again. Every plain delete door, local, batch, port,
//! replayed, publishing or demoting, meets [`reject_audience_edit_delete`],
//! and every edge removal [`reject_audience_edit_unlink`]. A privacy erase
//! keeps the edit, erased, instead ([`super::audience_erase`]).
//!
//! The root's own erase takes its edits with it
//! ([`tear_root_edits_in_txn`]): an edit of a root that is gone folds into
//! no one's read. That tear passes the guards on an explicit pass it holds
//! for each edit it tears, never on what the root's liveness says, since
//! the root still stands while its derived rows go.

use super::audience_events::{AudienceEvent, audience_event};
use super::*;
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::Store;
use crate::vault::live_entity_row_in_txn;
use std::cell::RefCell;

/// The bound a plain delete or unlink of a kept edit meets.
pub(crate) const AUDIENCE_EDIT_BOUND: &str = "a thread audience edit stays while its thread's root lives; erase the thread or its people instead";

thread_local! {
    /// The edits their root's erase is tearing on this thread now. A write
    /// transaction runs on its caller's thread, so the tear the cascade
    /// calls reads its own pass back here.
    static TORN_WITH_ROOT: RefCell<BTreeSet<EntityId>> = const { RefCell::new(BTreeSet::new()) };
}

/// One edit's pass through its root's erase, held for the edit's own tear
/// and ended when dropped, on an error too.
struct TornWithRoot(EntityId);

impl TornWithRoot {
    fn begin(edit: EntityId) -> Self {
        TORN_WITH_ROOT.with(|torn| torn.borrow_mut().insert(edit));
        Self(edit)
    }
}

impl Drop for TornWithRoot {
    fn drop(&mut self) {
        TORN_WITH_ROOT.with(|torn| torn.borrow_mut().remove(&self.0));
    }
}

/// The audience edit the row `id` stores, whether it reads live or not:
/// `None` for no row, any row but a TURN, and a TURN that carries none. Any
/// other row is known by its type byte alone, so its body is never copied.
fn stored_edit_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<AudienceEvent>> {
    let event =
        crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |raw| {
            match raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) {
                Some(body) if raw.first() == Some(&ENTITY_TYPE_TURN) => audience_event(body),
                _ => Ok(None),
            }
        })?;
    Ok(event.flatten())
}

/// The root that keeps the TURN `id` as one of its audience edits: while
/// `id` is a live TURN carrying an edit and the edit's root a live TURN. A
/// shell, a stale row, any other row and an edit its root's erase is
/// tearing now are kept by none.
pub(super) fn kept_root_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    if TORN_WITH_ROOT.with(|torn| torn.borrow().contains(id)) {
        return Ok(None);
    }
    let Some(event) = stored_edit_in(store, txn, id)? else {
        return Ok(None);
    };
    let live_turn = |turn: &EntityId| -> Result<bool> {
        Ok(live_entity_row_in_txn(store, txn, turn)?.live_type() == Some(ENTITY_TYPE_TURN))
    };
    Ok((live_turn(id)? && live_turn(&event.root)?).then_some(event.root))
}

/// The typed refusal [`AUDIENCE_EDIT_BOUND`] names.
fn kept() -> Error {
    crate::error::RecordError::ConversationState(AUDIENCE_EDIT_BOUND).into()
}

/// Refuses a plain delete of the TURN `id` while it is an audience edit its
/// live root keeps. It passes once the root is absent, a shell or stale.
pub(crate) fn reject_audience_edit_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    match kept_root_in(store, txn, id)? {
        Some(_) => Err(kept()),
        None => Ok(()),
    }
}

/// The refusal a removal of `src`'s `kind` edge to `tgt` meets, `None` when
/// it meets none: an `About` edge from a kept audience edit to the root that
/// keeps it is how the fold finds the edit.
pub(crate) fn audience_edit_unlink_refusal(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<Option<Error>> {
    Ok((kind == EdgeKind::About && kept_root_in(store, txn, src)? == Some(*tgt)).then(kept))
}

/// Refuses that removal ([`audience_edit_unlink_refusal`]).
pub(crate) fn reject_audience_edit_unlink(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<()> {
    audience_edit_unlink_refusal(store, txn, src, kind, tgt)?.map_or(Ok(()), Err)
}

/// Tears every audience edit of the TURN `root` as the root's own erase
/// runs, before the root's edges go, each on its pass through the guards
/// above. Reached through the derived-row eraser of both delete doors, soft
/// and hard, local and replayed. Only a TURN whose edit names this root
/// goes; any other `About` source stays.
pub(super) fn tear_root_edits_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    root: &EntityId,
) -> Result<()> {
    let sources: Vec<EntityId> = crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        root,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::About),
        None,
    )?
    .map(|edge| edge.map(|edge| edge.target))
    .collect::<Result<_>>()?;
    for edit in sources {
        if stored_edit_in(store, txn, &edit)?.is_none_or(|event| event.root != *root) {
            continue;
        }
        // A held edit stays, folding into no one's read: the root's erase
        // never fails on its edits.
        if crate::store::legal_hold::held_in_txn(store, txn, edit.as_bytes())? {
            continue;
        }
        let _torn = TornWithRoot::begin(edit);
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &edit)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &edit, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    Ok(())
}
