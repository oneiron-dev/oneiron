//! One-snapshot checks and served words for a bound extraction generation step.

use std::collections::BTreeSet;

use super::DreamerAttemptBinding;
use super::extraction_evidence::{bound_branch_error, check_turn_evidence};
use super::extraction_steps::ExtractionStepRequest;
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::extraction_pack::{BoundBranchInput, project_bound_branch};
use crate::dreamer_consolidation::extraction_step::{
    ExtractionStepPiece, PreparedExtractionStep, prepare_bound_step,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::{
    extraction_reader_scope_in_txn, extraction_turn_read, queued_extraction_branch_in_txn,
};

impl DreamerAttemptBinding {
    /// Checks every locator and retains only its served words before borrowing a backend.
    pub(super) fn checked_extraction_step(
        &self,
        input: &ExtractionStepRequest,
    ) -> MemoryResult<(PreparedExtractionStep, EntityId)> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let turn_read = extraction_turn_read(&read, None)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let _turn_pins = turn_read
            .as_ref()
            .map(crate::claim::ScopedRead::prepare_point_read::<MemoryError>)
            .transpose()?;
        let turn_read = turn_read.as_ref().unwrap_or(&read);
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
            let mut pieces = Vec::with_capacity(input.evidence.len());
            let mut turns = BTreeSet::new();
            for evidence in &input.evidence {
                let (turn, served) = check_turn_evidence(
                    &memory,
                    (&read, turn_read),
                    txn,
                    reader_scope.as_ref(),
                    evidence,
                    (scope, &branch),
                )?;
                if !turns.insert(turn) {
                    return Err(MemoryError::bad_request(
                        "an extraction step cites each TURN once",
                    ));
                }
                let (start, text) = match served.spans.into_iter().next() {
                    Some(span) => (span.start, span.text),
                    None => (0, String::new()),
                };
                pieces.push(ExtractionStepPiece {
                    turn,
                    start,
                    text,
                    version: evidence.version.clone(),
                });
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
            let prepared = prepare_bound_step(vault, txn, &read, &bound, &pieces, input.page)?;
            Ok((prepared, branch.subject().unwrap_or_else(|| self.attempt())))
        })?;
        Ok(checked.value)
    }
}
