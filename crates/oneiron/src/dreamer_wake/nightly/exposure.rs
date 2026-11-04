//! What each planned TURN's text may be read beside in another
//! conversation (FIX 7524, Engine ruling C): its PROJECT, the stored
//! position the scoped read doors select, and the relationship every
//! witnessed MESSAGE it is read from is scoped to. A thing's parts combine
//! across conversations only where both agree. A TURN whose project does
//! not decode or is not exactly one, or one of whose MESSAGEs is private or
//! has a relationship scope that does not decode, has no exposure: its part
//! stays in its own conversation's child, as before. Splitting is lossless;
//! nothing here refuses or drops a TURN.
//!
//! A TURN of a private thread also carries the people who read it (FIX
//! 7730): its thread's whole audience now, when each of them reads it under
//! the CONTENT rule. Parts of one private thread's thing share a line only
//! where their TURNs agree on project, relationships and these readers, so
//! one call never reads words of that thread beside words fewer or other
//! people read.

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
    /// On a private thread, the people who read it (FIX 7730): the thread's
    /// audience now, when every one of them reads this TURN. `None` off a
    /// private thread, and on one where some member does not read it or the
    /// read fails: such a part shares no line.
    pub(super) readers: Option<BTreeSet<EntityId>>,
}

impl Exposure {
    /// The exposure of a part whose TURNs carry `exposures`: one project,
    /// every relationship any of them reads, and their readers where every
    /// one names the same; `None` when one has none or they span projects.
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
            if exposure.readers != part.readers {
                part.readers = None;
            }
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
    let mut audiences = BTreeMap::new();
    partitions
        .iter()
        .flat_map(|partition| &partition.turns)
        .map(|turn| {
            (
                turn.turn_id,
                exposure_in(vault, txn, turn.turn_id, &mut audiences).unwrap_or_default(),
            )
        })
        .collect()
}

/// Each private thread's audience now, by its root, read once.
type Audiences = BTreeMap<EntityId, Option<BTreeSet<EntityId>>>;

fn exposure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    audiences: &mut Audiences,
) -> Result<Option<Exposure>> {
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
        readers: readers_in(vault, txn, turn, body, audiences),
    }))
}

/// The people who read `turn`, a TURN whose stored body is `body`, when it
/// is of a private thread whose whole audience now reads it under the
/// CONTENT rule (FIX 7730); `None` off a private thread, where one member
/// does not read it, and where a read fails.
fn readers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    body: &[u8],
    audiences: &mut Audiences,
) -> Option<BTreeSet<EntityId>> {
    let binding = crate::workspace_roster::thread_binding(body).ok()??;
    let audience = match audiences.get(&binding.root) {
        Some(audience) => audience.clone(),
        None => {
            let audience = crate::workspace_roster::thread_audience_now_in(
                vault,
                txn,
                binding.room,
                binding.root,
            )
            .ok()
            .flatten()
            .filter(|audience| !audience.is_empty());
            audiences.insert(binding.root, audience.clone());
            audience
        }
    }?;
    let viewers: Vec<EntityId> = audience.iter().copied().collect();
    crate::workspace_roster::thread_turn_readable_with_read_in(
        vault,
        &vault.store.read(),
        txn,
        binding.root,
        turn,
        &viewers,
    )
    .ok()?
    .then_some(audience)
}
