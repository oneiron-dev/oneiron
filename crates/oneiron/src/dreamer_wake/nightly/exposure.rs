//! What each planned TURN's text may be read beside in another
//! conversation (FIX 7524, Engine ruling C): its PROJECT, the stored
//! position the scoped read doors select, and the relationship every
//! witnessed MESSAGE it is read from is scoped to. A thing's parts combine
//! across conversations only where both agree. A TURN whose project does
//! not decode or is not exactly one, or one of whose MESSAGEs is private or
//! has a relationship scope that does not decode, has no exposure: its part
//! stays in its own conversation's child, as before. Splitting is lossless;
//! nothing here refuses or drops a TURN.

use std::collections::{BTreeMap, BTreeSet};

use crate::claim::RelationshipRead;
use crate::dreamer_consolidation::ConsolidationPartitionPlan;
use crate::edge::EdgeKind;
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::{EntityId, Result, Vault};

/// The exposure a TURN's text carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Exposure {
    pub(super) project: EntityId,
    /// The relationships its witnessed MESSAGEs are scoped to; empty for
    /// the vault's own words.
    pub(super) relationships: BTreeSet<EntityId>,
}

impl Exposure {
    /// The exposure of a part whose TURNs carry `exposures`: one project,
    /// every relationship any of them reads; `None` when one has none or
    /// they span projects.
    pub(super) fn of_part(exposures: &[Option<&Self>]) -> Option<Self> {
        let (first, rest) = exposures.split_first()?;
        let mut part = (*first)?.clone();
        for exposure in rest {
            let exposure = (*exposure)?;
            if exposure.project != part.project {
                return None;
            }
            part.relationships
                .extend(exposure.relationships.iter().copied());
        }
        Some(part)
    }
}

/// Each planned TURN's exposure at the planning snapshot; `None` where it
/// has none. A read that fails leaves that TURN with none, never failing
/// the night's planning.
pub(super) fn exposures_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    partitions: &[ConsolidationPartitionPlan],
) -> BTreeMap<EntityId, Option<Exposure>> {
    partitions
        .iter()
        .flat_map(|partition| &partition.turns)
        .map(|turn| {
            (
                turn.turn_id,
                exposure_in(vault, txn, turn.turn_id).unwrap_or_default(),
            )
        })
        .collect()
}

fn exposure_in(vault: &Vault, txn: &heed::RoTxn<'_>, turn: EntityId) -> Result<Option<Exposure>> {
    let Some(raw) = vault.get_raw_in(txn, &turn)? else {
        return Ok(None);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .unwrap_or_default();
    let Some(project) = crate::dreamer_consolidation::resources::stored_project(
        &vault.store,
        txn,
        turn,
        header.entity_type,
        body,
    )?
    else {
        return Ok(None);
    };
    let mut relationships = BTreeSet::new();
    for message in vault.filtered_edge_peers(
        txn,
        EdgeDirection::In,
        &turn,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_MESSAGE),
    )? {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &message)?.is_live() {
            continue;
        }
        let Some(raw) = vault.get_raw_in(txn, &message)? else {
            return Ok(None);
        };
        match crate::claim::relationship_read(&vault.store, txn, &message, &raw)? {
            RelationshipRead::Decided(true) => {}
            RelationshipRead::Gated {
                space,
                private: false,
                ..
            } => relationships.extend(space.into_iter().flatten()),
            _ => return Ok(None),
        }
    }
    Ok(Some(Exposure {
        project,
        relationships,
    }))
}
