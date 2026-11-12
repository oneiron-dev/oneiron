//! What the author writer made of each AGENT_DEF put an agent's batch staged
//! (ARCH-0053:20), for the write receipt of the door that committed the
//! batch: active, a proposal, or a proposed change stored at its own id.

use std::sync::{Arc, Mutex};

use crate::core_write::{AgentDefinitionWriteDisposition, AgentDefinitionWriteReceipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The receipts of the AGENT_DEF puts an agent's batch staged, each by the id
/// it was staged at. The author writer fills them in the transaction that
/// applies the batch; the committing door reads them once that transaction
/// has committed. A batch with no agent author holds none.
#[derive(Debug, Clone, Default)]
pub struct AgentDefinitionWriteReceipts(Arc<Mutex<Vec<(EntityId, AgentDefinitionWriteReceipt)>>>);

impl AgentDefinitionWriteReceipts {
    /// The receipt of the AGENT_DEF put staged at `staged`; `None` for a put
    /// that was no agent's AGENT_DEF put.
    #[must_use]
    pub fn get(&self, staged: &EntityId) -> Option<AgentDefinitionWriteReceipt> {
        self.0
            .lock()
            .ok()?
            .iter()
            .find(|(id, _)| id == staged)
            .map(|(_, receipt)| receipt.clone())
    }

    /// The receipt of each AGENT_DEF put staged at `staged`, in order: the
    /// n-th put staged at an id takes the n-th receipt the writer recorded for
    /// that id, so two puts at one id each name what they became. `None` for
    /// a put the writer recorded nothing for.
    #[must_use]
    pub fn in_staged_order(&self, staged: &[EntityId]) -> Vec<Option<AgentDefinitionWriteReceipt>> {
        let Ok(recorded) = self.0.lock() else {
            return vec![None; staged.len()];
        };
        let mut taken = vec![false; recorded.len()];
        staged
            .iter()
            .map(|id| {
                let index =
                    (0..recorded.len()).find(|&index| !taken[index] && recorded[index].0 == *id)?;
                taken[index] = true;
                Some(recorded[index].1.clone())
            })
            .collect()
    }

    /// Replaces every receipt: a writer that runs again holds only its last
    /// run's.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] when a writer panicked holding them.
    pub(crate) fn replace(
        &self,
        receipts: Vec<(EntityId, AgentDefinitionWriteReceipt)>,
    ) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| Error::InvariantViolation("agent definition write receipts"))? = receipts;
        Ok(())
    }
}

/// The receipt of a definition stored at the id it was put at, with
/// `approval_status`.
pub(crate) fn stored_at_its_id(
    approval_status: crate::claim::ClaimApprovalStatus,
) -> AgentDefinitionWriteReceipt {
    let disposition = match approval_status {
        crate::claim::ClaimApprovalStatus::Auto | crate::claim::ClaimApprovalStatus::Approved => {
            AgentDefinitionWriteDisposition::Active
        }
        crate::claim::ClaimApprovalStatus::Proposed
        | crate::claim::ClaimApprovalStatus::Rejected => AgentDefinitionWriteDisposition::Proposed,
    };
    AgentDefinitionWriteReceipt {
        disposition,
        proposal_id: None,
    }
}

/// The receipt of a put stored as a proposed change at `proposal`.
pub(crate) fn stored_as_proposed_change(proposal: &EntityId) -> AgentDefinitionWriteReceipt {
    AgentDefinitionWriteReceipt {
        disposition: AgentDefinitionWriteDisposition::ProposedChange,
        proposal_id: Some(proposal.to_hex()),
    }
}
