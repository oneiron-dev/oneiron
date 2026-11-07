//! Facet rule C (arch-0022:139): an ASSET_TEXT written from source ASSETs is
//! born under their facet, and is read only beside every one of them.
//!
//! A source-bound text carries one `FacetOf` stamp, copied at its birth from
//! the one facet all its sources were born under; nothing places it later.
//! Its sources are its `DerivedFrom` targets, judged at every read: an edge
//! added later only narrows who reads it, and a source lost withdraws it. A
//! text born bound to no source carries one `FacetOf` stamp too, the batch
//! mask or the vault default its birth transaction stamped, and beside it
//! the immutable record that it was born source-free (FIX 8741), so its
//! words read as its own and a text whose sources are gone never does. A
//! source-free text born before that keeps its own substrate facet and no
//! birth stamp.

use super::{SCOPE_RECORD, birth_facet};
use crate::EntityId;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{
    EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, TombstoneStoreRead,
};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::side_table::{self, Named, SideTable};
use crate::store::{ManifestDbs, Store};

/// The facet each source-free ASSET_TEXT was born under, by the text's id:
/// written only in its birth transaction, beside its `FacetOf` stamp, and
/// retired with its record-scope stamp (FIX 8741).
const SOURCE_FREE_BIRTH: SideTable<EntityId, EntityId, Named> =
    SideTable::new(&side_table::SCOPE_SOURCE_FREE_TEXT);

/// The facet ASSET_TEXT `id`'s record position names: the one it was born
/// under, as its `FacetOf` stamp or, where that edge is gone, its
/// source-free birth record holds it, or its own substrate facet for a text
/// born unplaced.
pub(crate) fn text_facet(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<EntityId> {
    if let Some(facet) = birth_facet(store, txn, id)? {
        return Ok(facet);
    }
    match SOURCE_FREE_BIRTH.get(store, txn, &id)? {
        Some(facet) => Ok(facet),
        None => crate::claim::substrate_facet_id(id),
    }
}

/// Whether ASSET_TEXT `id` was born bound to no source: placed by no
/// `FacetOf` stamp (a text born unplaced), or stamped at a source-free birth
/// under the facet its birth record names (FIX 8741). A text stamped beside
/// its sources was not, whatever sources it has left.
pub(crate) fn born_source_free(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<bool> {
    Ok(match birth_facet(store, txn, id)? {
        None => true,
        Some(facet) => SOURCE_FREE_BIRTH.get(store, txn, &id)? == Some(facet),
    })
}

/// Records, in the birth transaction that stamped ASSET_TEXT `id` under
/// `facet` with no source named, that it was born source-free (FIX 8741).
/// A replicated text is never stamped here: its record is restored only
/// beside the record position its verified origin carries
/// (`origin_positions`).
pub(crate) fn stamp_source_free_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    facet: EntityId,
) -> Result<()> {
    SOURCE_FREE_BIRTH.put(store, txn, &id, &facet)
}

/// Retires `id`'s source-free birth record with its record-scope stamp, so a
/// later same-id write never inherits it.
pub(crate) fn retire_source_free_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    SOURCE_FREE_BIRTH.delete(store, txn, &id)?;
    Ok(())
}

/// The facet a text written from `sources` is born under: the one every
/// source was born under. A source that is not a live ASSET born under a
/// facet, or sources under two facets, refuse the birth (ruling c).
pub(crate) fn sources_birth_facet(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> Result<EntityId> {
    let mut born = None;
    for source in sources {
        let state = store.port_deletion_state(txn, source)?;
        let placed = match store.port_entity_record(txn, source)? {
            Some(row) if row.entity_type == ENTITY_TYPE_ASSET && !state.deleted && !state.stale => {
                birth_facet(store, txn, *source)?
            }
            _ => None,
        };
        let Some(facet) = placed else {
            return Err(Error::InvalidClaimBody(
                "asset text source is not a placed asset",
            ));
        };
        if born.is_some_and(|born| born != facet) {
            return Err(Error::InvalidClaimBody(
                "asset text sources sit in different facets",
            ));
        }
        born = Some(facet);
    }
    born.ok_or(Error::InvalidClaimBody("asset text birth names no source"))
}

/// Whether a stamp `id -FacetOf-> facet` onto ASSET_TEXT `id` restores its
/// birth: the stamp it carries, or, where that edge is gone, the facet its
/// record position was born under. Any other stamp, a first one included,
/// would place the text after its birth. A `replay` of a text that holds no
/// record position here, a row that arrived replicated, restores the stamp
/// its origin wrote with it.
pub(crate) fn restores_birth(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    facet: EntityId,
    replay: bool,
) -> Result<bool> {
    if let Some(stamp) = birth_facet(store, txn, id)? {
        return Ok(stamp == facet);
    }
    if facet == crate::claim::substrate_facet_id(id)? {
        return Ok(false);
    }
    Ok(match SCOPE_RECORD.get(store, txn, &id)? {
        Some(stamp) => {
            stamp.version == 2
                && stamp.kind == ENTITY_TYPE_ASSET_TEXT
                && stamp.birth_facet == *facet.as_bytes()
        }
        None => replay,
    })
}

/// Whether every source ASSET_TEXT `id` was written from, as `view` holds it
/// in `txn`, is a live ASSET that `admit` passes. `None` for a text with no
/// `DerivedFrom` edge that was born bound to no source (an imported image's
/// caption), whose words are its own: one born unplaced, or one stamped at
/// its source-free birth (FIX 8741). A text born beside its sources with no
/// source left passes none.
pub(crate) fn sources_admitted_in(
    view: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    mut admit: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<Option<bool>> {
    let mut sources = view
        .port_edges(
            txn,
            id,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            None,
        )?
        .peekable();
    if sources.peek().is_none() {
        return Ok((!born_source_free(view, txn, *id)?).then_some(false));
    }
    for edge in sources {
        let source = edge?.target;
        let state = view.port_deletion_state(txn, &source)?;
        let Some(row) = view.port_entity_record(txn, &source)? else {
            return Ok(Some(false));
        };
        if row.entity_type != ENTITY_TYPE_ASSET
            || state.deleted
            || state.stale
            || !admit(&source, &row)?
        {
            return Ok(Some(false));
        }
    }
    Ok(Some(true))
}
