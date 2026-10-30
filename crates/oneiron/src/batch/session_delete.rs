//! A room's delete of a row only it staged (FIX 10763).
//!
//! A raw handle bound inside an off-record session deletes a row its room
//! put, which base never held, in the room: the row, its type and time
//! index rows, its identity and name hints, its text, its vector and its
//! graph node go from the room's overlay. Base holds nothing of it, so
//! nothing is written there, and close drops the delete with the room. A
//! row base holds keeps base's delete.

use heed::RwTxn;

use super::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::SessionStoreView;
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
    crate::ingest::reindex_identity_hints(view, wtxn, id, None)?;
    crate::ports::reindex_named_entities(view, wtxn, id, None)?;
    crate::bm25::deindex_text(view, wtxn, id)?;
    if view.vectors.stages_row(id.as_bytes()) {
        crate::hnsw::hnsw_deindex(view, wtxn, id)?;
        view.vectors.delete(wtxn, id.as_bytes())?;
    }
    view.entities.delete(wtxn, id.as_bytes())?;
    Ok(())
}
