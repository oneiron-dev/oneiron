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
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};

/// Whether the stored row `id`, with header and body `raw` as `view` holds
/// it, sits in one of `facets`. A TASK sits in the facet its birth stamp
/// names; any row sits in each facet a `FacetOf` edge of its names, and, for a room and
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
        if set.contains(&ScopeId(edge?.target)) {
            return Ok(true);
        }
    }
    // A peer can add a room edge to a row it did not write, and under the
    // any-facet rule an added room only widens (Astra on #1432): a row whose
    // edges name two rooms sits in neither.
    let room = match header.entity_type {
        ENTITY_TYPE_CONVERSATION => Some(id),
        ENTITY_TYPE_TURN => one_room(out_targets(view, txn, id, EdgeKind::ChildOf)?),
        ENTITY_TYPE_MESSAGE => match out_targets(view, txn, id, EdgeKind::BelongsTo)? {
            rooms if !rooms.is_empty() => one_room(rooms),
            _ => {
                let mut rooms = Vec::new();
                for turn in out_targets(view, txn, id, EdgeKind::PartOf)? {
                    rooms.extend(out_targets(view, txn, turn, EdgeKind::ChildOf)?);
                }
                one_room(rooms)
            }
        },
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

/// The one room `rooms` names, if they name exactly one.
fn one_room(rooms: Vec<EntityId>) -> Option<EntityId> {
    let first = *rooms.first()?;
    rooms.iter().all(|room| *room == first).then_some(first)
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
