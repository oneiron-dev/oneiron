//! Core half of `store::claim_refinement_control`: its store-layer items live in `oneiron_store::claim_refinement_control` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::claim_refinement_control::*;

use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::{
    EntityId,
    error::Result,
    registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL},
};
use serde::{Deserialize, Serialize};

/// Content-free refinement control row for one candidate.
pub(crate) const CONTROL: SideTable<EntityId, RefinementControl, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_CONTROL);

pub(crate) fn read_control(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RefinementControl>> {
    CONTROL.get(store, txn, id)
}

pub(crate) fn put_control(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    control: &RefinementControl,
) -> Result<()> {
    CONTROL.put(store, txn, id, control)
}

pub(crate) fn refinement_control_scope_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(read_control(store, txn, id)?.is_some_and(|row| row.state != RefinementState::Erased))
}

pub(crate) fn retire_refinement_control(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(mut row) = read_control(store, txn, id)? else {
        return Ok(false);
    };
    if row.state == RefinementState::Erased {
        return Ok(false);
    }
    if matches!(row.target, RefinementTarget::Skill { .. }) {
        // The offer's source assertion is not a permanent deletion marker.
        // Retain only the content-free typed control/erased-ID fact.
        SHARED_DELTA.delete(store, txn, id)?;
    }
    row.state = RefinementState::Erased;
    put_control(store, txn, id, &row)?;
    Ok(true)
}

/// Owner-adjudicated held-out claim labels (sorted, unique hex ids) reserved
/// for one claim base.
pub(crate) const RESERVE: SideTable<EntityId, Vec<String>, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_CLAIM_REFINEMENT_RESERVE);

/// Shared-skill merge delta computed for one candidate. Crate-visible because
/// retiring a skill refinement's control drops its offered delta row.
pub(crate) const SHARED_DELTA: SideTable<EntityId, SharedSkillDelta, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_SHARED_DELTA);

/// The control row survives as an identifier-only erased fence. The native
/// Proposed CLAIM owns all branch payload bytes; ASSET custody owns rulings.
pub(crate) fn claim_refinement_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(refinement_control_scope_exists(store, txn, id)? || RESERVE.contains(store, txn, id)?)
}

pub(crate) fn erase_claim_refinement_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let had_control = retire_refinement_control(store, txn, id)?;
    let had_reserve = RESERVE.delete(store, txn, id)?;
    Ok(had_control || had_reserve)
}
