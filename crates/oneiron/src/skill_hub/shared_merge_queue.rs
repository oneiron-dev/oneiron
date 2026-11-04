//! The owner's reads of offered shared-skill deltas, and the owner's discard
//! of one no merge has admitted.
use super::refinement_admission::{
    RefinementState, RefinementTarget, read_control, retire_refinement_control,
};
use super::shared_delta::SHARED_DELTA;
use super::{SharedSkillDelta, package_codec::invalid};
use crate::{Vault, consent::AuthenticatedOwner, entity_id::EntityId, error::Result};

/// Where an offered shared-skill delta stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedSkillMergeState {
    /// No merge has ruled on it: never asked, or waiting on the owner's
    /// answer.
    Pending,
    /// A merge ruled it out. It may be asked again.
    Refused,
    /// A merge put it in force.
    Admitted,
}

/// One offered delta and where it stands.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SharedSkillMergeEntry {
    pub delta: SharedSkillDelta,
    pub state: SharedSkillMergeState,
}

impl Vault {
    /// Every offered shared-skill delta no merge has ruled on, in candidate
    /// order.
    pub fn pending_shared_skill_merges(&self) -> Result<Vec<SharedSkillDelta>> {
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for row in SHARED_DELTA.iter_from(&self.store, &txn, &[])? {
            let (candidate, delta) = row?;
            if read_control(&self.store, &txn, &candidate)?
                .is_some_and(|control| control.state == RefinementState::Pending)
            {
                pending.push(delta);
            }
        }
        Ok(pending)
    }

    /// The delta offered under `candidate` and where it stands; `None` when
    /// none is offered, or its offer was erased or discarded.
    pub fn shared_skill_merge_entry(
        &self,
        candidate: &EntityId,
    ) -> Result<Option<SharedSkillMergeEntry>> {
        let txn = self.store.env.read_txn()?;
        let Some(delta) = SHARED_DELTA.get(&self.store, &txn, candidate)? else {
            return Ok(None);
        };
        let state = match read_control(&self.store, &txn, candidate)?.map(|control| control.state) {
            Some(RefinementState::Pending) => SharedSkillMergeState::Pending,
            Some(RefinementState::Refused) => SharedSkillMergeState::Refused,
            Some(RefinementState::Admitted) => SharedSkillMergeState::Admitted,
            Some(RefinementState::Erased) | None => return Ok(None),
        };
        Ok(Some(SharedSkillMergeEntry { delta, state }))
    }

    /// The owner discards the delta offered under `candidate`. Its control
    /// becomes the erased fence a deleted candidate leaves and its delta row
    /// goes, so no merge is asked on it again; the candidate revision stays
    /// readable as a Candidate. A merge that admitted it rolls back instead
    /// ([`Self::roll_back_shared_skill_merge`]). `false` when no offer is
    /// open under `candidate`.
    pub fn discard_shared_skill_delta(
        &self,
        owner: &AuthenticatedOwner,
        candidate: &EntityId,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let Some(control) = read_control(&self.store, txn, candidate)? else {
                return Ok(false);
            };
            if !matches!(control.target, RefinementTarget::Skill { .. }) {
                return Ok(false);
            }
            match control.state {
                RefinementState::Pending | RefinementState::Refused => {
                    retire_refinement_control(&self.store, txn, candidate)
                }
                RefinementState::Admitted => Err(invalid(
                    "an admitted shared merge rolls back; it is not discarded",
                )),
                RefinementState::Erased => Ok(false),
            }
        })
    }
}
