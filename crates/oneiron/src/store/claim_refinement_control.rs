//! A refinement candidate's content-free control row, the claim base's
//! reserved held-out labels and the offered shared-skill delta, with the
//! scope test and the erase a deletion makes of them. The skill hub
//! (`skill_hub::{refinement_admission, claim_refinement, shared_delta,
//! shared_gate, shared_merge_queue}`) writes and reads these rows; the
//! store's erase markers, replay, active store and deindex test and erase
//! them.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefinementState {
    Pending,
    Refused,
    Admitted,
    Erased,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RefinementTarget {
    Skill { base: String, fork: String },
    Claim { base: String, proposal: String },
}
impl RefinementTarget {
    pub(crate) fn base(&self) -> &str {
        match self {
            Self::Skill { base, .. } | Self::Claim { base, .. } => base,
        }
    }
    pub(crate) fn kind(&self) -> u8 {
        match self {
            Self::Skill { .. } => ENTITY_TYPE_SKILL,
            Self::Claim { .. } => ENTITY_TYPE_CLAIM,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefinementControl {
    pub(crate) target: RefinementTarget,
    pub(crate) resident: Option<String>,
    pub(crate) base_binding: String,
    pub(crate) proposal_binding: String,
    pub(crate) state: RefinementState,
}
impl RefinementControl {
    pub(crate) fn claim(
        base: EntityId,
        candidate: EntityId,
        resident: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Claim {
                base: base.to_hex(),
                proposal: candidate.to_hex(),
            },
            resident: Some(resident.to_hex()),
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
    pub(crate) fn skill(
        base: EntityId,
        fork: EntityId,
        base_binding: String,
        proposal_binding: String,
    ) -> Self {
        Self {
            target: RefinementTarget::Skill {
                base: base.to_hex(),
                fork: fork.to_hex(),
            },
            resident: None,
            base_binding,
            proposal_binding,
            state: RefinementState::Pending,
        }
    }
}
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

/// Both lanes offer bytes to the receiving base. Neither grants access to the sender's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SharedSkillLane {
    FederationMergeBack,
    CompanyPullRequest,
}
/// Durable offered delta; author and foreign fork are source assertions, never authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSkillDelta {
    pub candidate: String,
    pub base: String,
    pub base_binding: String,
    pub content_hash: String,
    pub lane: SharedSkillLane,
    pub submitted_by: String,
    pub submitted_fork: String,
}
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
