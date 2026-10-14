//! The one facet rule (owner ruling FACET-READ = A). A facet is an opt-in
//! limit on what an agent's or a room's credential reads, never the owner's:
//! a credential narrowed to a set of facets reads a row only when the row sits
//! in one of them. MCP and every read lane judge a row here, so the two never
//! disagree.

use super::record_scope::{MachineHistoryScope, scope_for_blob};
use super::{ScopeAxis, ScopeId};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
};
use crate::side_table::{self, HexId, Raw, SideTable, SideTableDbs};
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};

/// A federated `FacetOf` stamp that arrived ahead of its source row, under the
/// lane of the sender that brought it. The read rule skips it until that
/// sender brings the row, the row's own birth carries the stamp, or a writer
/// that may place the row writes it. The export selector still reads it (H2).
const PARKED_STAMP: SideTable<(HexId, HexId, String), (), Raw> =
    SideTable::new(&side_table::FEDERATION_PARKED_FACET_STAMP);

/// Whether the stored row `id`, with header and body `raw` as `view` holds
/// it, sits in one of `facets`. A TASK sits in the facet its birth stamp
/// names; any row sits in each facet a `FacetOf` edge of its names, unless
/// the stamp is parked, and, for a room and
/// each MESSAGE or TURN said there, in each facet of the room. A row with
/// several facets is readable when any one is in the set; a row that names
/// none sits in no facet. A whole axis reads every row and an empty one reads
/// none.
pub(crate) fn facets_admit_in(
    vault: &Vault,
    view: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    facets: &ScopeAxis<ScopeId>,
) -> Result<bool> {
    let set = match facets {
        ScopeAxis::All => return Ok(true),
        ScopeAxis::Some(set) if !set.is_empty() => set,
        _ => return Ok(false),
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
    if header.entity_type == ENTITY_TYPE_TASK
        && scope_for_blob(view, txn, id, raw)?
            .is_some_and(|scope| !scope.facets.meet(facets).is_bottom())
    {
        return Ok(true);
    }
    for edge in view.port_edges(txn, &id, EdgeDirection::Out, Some(EdgeKind::FacetOf), None)? {
        let facet = edge?.target;
        if set.contains(&ScopeId(facet)) && !stamp_parked(view, txn, id, facet)? {
            return Ok(true);
        }
    }
    let room = match header.entity_type {
        ENTITY_TYPE_CONVERSATION => Some(id),
        ENTITY_TYPE_TURN => out_targets(view, txn, id, EdgeKind::ChildOf)?
            .first()
            .copied(),
        // A MESSAGE names its room directly and through its TURN. It sits in
        // a room only when the two agree, as the deletion resolver reads it:
        // a room edge added to a row someone else said only withholds it.
        ENTITY_TYPE_MESSAGE => {
            let mut rooms = out_targets(view, txn, id, EdgeKind::BelongsTo)?;
            for part in out_targets(view, txn, id, EdgeKind::PartOf)? {
                if view
                    .entities()
                    .get(txn, part.as_bytes())?
                    .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
                {
                    rooms.push(part);
                } else {
                    rooms.extend(out_targets(view, txn, part, EdgeKind::ChildOf)?);
                }
            }
            let first = rooms.first().copied();
            first.filter(|first| rooms.iter().all(|room| room == first))
        }
        _ => None,
    };
    let Some(room) = room else {
        return Ok(false);
    };
    Ok(crate::workspace_roster::room_facets_in(vault, txn, room)?
        .is_some_and(|room| !room.meet(facets).is_bottom()))
}

/// The targets of `id`'s outgoing `kind` edges.
fn out_targets(
    view: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    view.port_edges(txn, &id, EdgeDirection::Out, Some(kind), None)?
        .map(|edge| edge.map(|edge| edge.target))
        .collect()
}

/// The key every parked copy of the stamp `src -FacetOf-> facet` starts with.
fn stamp_prefix(src: EntityId, facet: EntityId) -> String {
    format!("{}{}", src.to_hex(), facet.to_hex())
}

fn stamp_parked(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    facet: EntityId,
) -> Result<bool> {
    Ok(PARKED_STAMP
        .iter_raw_from(dbs, txn, stamp_prefix(src, facet).as_bytes())?
        .next()
        .transpose()?
        .is_some())
}

/// Parks the stamp `src -FacetOf-> facet` under the sender's `lane`.
pub(crate) fn park_stamp(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    src: EntityId,
    facet: EntityId,
    lane: &str,
) -> Result<()> {
    PARKED_STAMP.put(dbs, wtxn, &(HexId(src), HexId(facet), lane.to_owned()), &())
}

/// Lets the stamp `src -FacetOf-> facet` count, whichever senders parked it.
pub(crate) fn unpark_stamp(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    src: EntityId,
    facet: EntityId,
) -> Result<()> {
    for key in PARKED_STAMP.scan_keys(dbs, wtxn, stamp_prefix(src, facet).as_bytes())? {
        PARKED_STAMP.delete(dbs, wtxn, &key)?;
    }
    Ok(())
}

/// The facets of the stamps on `src` parked under `lane`.
pub(crate) fn parked_under(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    lane: &str,
) -> Result<Vec<EntityId>> {
    Ok(PARKED_STAMP
        .scan_keys(dbs, txn, src.to_hex().as_bytes())?
        .into_iter()
        .filter(|(_, _, by)| by == lane)
        .map(|(_, facet, _)| facet.0)
        .collect())
}

impl Vault {
    /// Whether the row `id` sits in one of `facets`, by the rule every read
    /// lane applies (`facets_admit_in`). A row that is not stored sits in
    /// none.
    pub fn row_in_facets(&self, id: &EntityId, facets: &ScopeAxis<ScopeId>) -> Result<bool> {
        if matches!(facets, ScopeAxis::All) {
            return Ok(true);
        }
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
            return Ok(false);
        };
        facets_admit_in(self, &self.store, &txn, *id, &raw, facets)
    }
}
