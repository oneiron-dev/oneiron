//! One-snapshot checks and served words for a bound extraction generation step.

use super::DreamerAttemptBinding;
use super::extraction_evidence::{bound_branch_error, check_turn_evidence};
use super::extraction_steps::ExtractionStepRequest;
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::extraction_pack::{BoundBranchInput, project_bound_branch};
use crate::dreamer_consolidation::extraction_step::{PreparedExtractionStep, prepare_bound_step};
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::{extraction_reader_scope_in_txn, queued_extraction_branch_in_txn};

impl DreamerAttemptBinding {
    /// Checks every locator and retains only its served words before borrowing a backend.
    pub(super) fn checked_extraction_step(
        &self,
        input: &ExtractionStepRequest,
    ) -> MemoryResult<(PreparedExtractionStep, EntityId)> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let reader_scope = extraction_reader_scope_in_txn(&memory, &txn, None)?;
        let checked = read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            let (scope, branch) = queued_extraction_branch_in_txn(vault, txn, self.attempt())?;
            let limit = vault
                .consolidation_selection_in_txn(txn)?
                .extraction_turns_per_child;
            if input.evidence.is_empty() || input.evidence.len() > limit {
                return Err(MemoryError::bad_request(format!(
                    "an extraction step needs between 1 and {limit} evidence entries"
                )));
            }
            let mut words = Vec::with_capacity(input.evidence.len());
            for evidence in &input.evidence {
                let (turn, served) = check_turn_evidence(
                    &memory,
                    &read,
                    txn,
                    reader_scope.as_ref(),
                    evidence,
                    (scope, &branch),
                )?;
                let text = served
                    .spans
                    .into_iter()
                    .map(|span| span.text)
                    .collect::<Vec<_>>()
                    .join("\n");
                words.push((turn, text));
            }
            let bound = project_bound_branch(
                vault,
                txn,
                &read,
                &BoundBranchInput {
                    attempt: self.lease.attempt(),
                    branch: &branch,
                    caller: None,
                    destination: None,
                },
            )
            .map_err(bound_branch_error)?;
            let prepared = prepare_bound_step(vault, txn, &read, &bound, &words)
                .map_err(bound_branch_error)?;
            Ok((prepared, branch.subject().unwrap_or_else(|| self.attempt())))
        })?;
        Ok(checked.value)
    }
}
