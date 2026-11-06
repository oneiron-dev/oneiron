//! A room's delete of a row only it staged (FIX 10763, FIX 11932, FIX 12012).
//!
//! A raw handle bound inside an off-record session deletes a row its room
//! put, which base never held, in the room: the row, its type and time
//! index rows, its identity and name hints, its text, its vector and its
//! graph node go from the room's overlay, and so does what in the room still
//! names it, as base's delete takes each: its revision rows, its phonetic
//! name rows, the room's edges from or to it, its staged position and its
//! session short-id alias; the dependency rows naming it as derived go the
//! way a regeneration replaces them, since base's delete keeps them. Inbound
//! DerivedFrom epochs and ASSET_TEXT are withdrawn in the room too (FIX 12029).
//! Its conversation-DAG pin is withdrawn, as base withdraws it. Base holds
//! nothing of it, so nothing is written there, and close drops the delete
//! with the room. A row base holds keeps base's delete.

use heed::RwTxn;

use super::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EdgeStoreStaging, EntityStoreRead};
use crate::store::{SessionStoreView, Store};
use crate::temporal::TimeRange;

/// Deletes `id` from `view`'s room, a row the room stages and base does not
/// hold.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for a row base holds or the room does not
/// stage, whose delete is base's; storage errors.
pub(super) fn stage_session_delete(
    view: &SessionStoreView<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !view.entities.stages_row(id.as_bytes())
        || EntityStoreRead::port_entity_raw(view.read().base(), wtxn, id)?.is_some()
    {
        return Err(Error::EntityNotFound);
    }
    let raw = EntityStoreRead::port_entity_raw(view, wtxn, id)?.ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    // Inbound derived rows lose their source while every edge and dependency
    // row still reads, as base's delete does (FIX 12029).
    let inbound_derived = EdgeStoreRead::port_edges(
        view,
        wtxn,
        id,
        EdgeDirection::In,
        Some(EdgeKind::DerivedFrom),
        None,
    )?
    .map(|row| row.map(|edge| edge.target))
    .collect::<Result<Vec<_>>>()?;
    let mut stale_marks = Vec::new();
    for dependent in inbound_derived {
        if dependent != *id {
            let write_view = view.write_snapshot()?;
            if let Some(mark) = crate::ports::withdraw_from_lost_source_in_session_txn(
                &write_view,
                wtxn,
                &dependent,
                id,
            )? {
                stale_marks.push(mark);
            }
        }
    }
    let write_view = view.write_snapshot()?;
    let view = &write_view;
    // The DAG pin is withdrawn while the row and its memberships still read,
    // as base's delete withdraws it before its edges go.
    let memberships = EdgeStoreRead::port_edges(
        view,
        wtxn,
        id,
        EdgeDirection::Out,
        Some(EdgeKind::ChildOf),
        None,
    )?
    .collect::<Result<Vec<_>>>()?;
    for edge in memberships {
        crate::conversation_dag::keep_membership_pin(view, wtxn, id, edge.kind, &edge.target)?;
    }
    super::delete_entity_index_rows(
        view,
        wtxn,
        id,
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    crate::store::identity_hints::reindex_identity_hints(view, wtxn, id, None)?;
    crate::ports::reindex_named_entities(view, wtxn, id, None)?;
    crate::store::text_index::deindex_text(view, wtxn, id)?;
    crate::vault::entity_revision::remove_entity_revisions(view, wtxn, id)?;
    super::delete_from_phonetic_postings(view, wtxn, id)?;
    super::delete_short_id_rows_for_id(view, wtxn, id)?;
    crate::ports::remove_dependency_rows_for_dependent_in_txn(view, wtxn, id)?;
    if view.vectors.stages_row(id.as_bytes()) {
        crate::hnsw::hnsw_deindex(view, wtxn, id)?;
        view.vectors.delete(wtxn, id.as_bytes())?;
    }
    unstage_room_edges(view, wtxn, id)?;
    crate::federation::record_scope::unstage_session_position(view, wtxn, *id)?;
    view.entities.delete(wtxn, id.as_bytes())?;
    // The marks allocate new keys; use the budget freed by source cleanup.
    for mark in stale_marks {
        mark.stage_in_txn(view, wtxn)?;
    }
    Ok(())
}

/// Takes the room's edges from or to `id`, both directions of each, as
/// base's delete takes the row's edges. An edge only base holds is base's
/// and stays.
fn unstage_room_edges(
    view: &SessionStoreView<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut staged = Vec::new();
    for direction in [EdgeDirection::Out, EdgeDirection::In] {
        for row in EdgeStoreRead::port_edges(view, wtxn, id, direction, None, None)? {
            let edge = row?;
            let (source, target) = match direction {
                EdgeDirection::In => (edge.target, *id),
                _ => (*id, edge.target),
            };
            if view
                .edges_out
                .stages_row(&Store::encode_edge_key(&source, edge.kind, &target))
            {
                staged.push((source, edge.kind, target));
            }
        }
    }
    for (source, kind, target) in staged {
        EdgeStoreStaging::port_remove_edge_rows(view, wtxn, &source, kind, &target)?;
    }
    Ok(())
}
