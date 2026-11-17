//! One-snapshot evidence checks for a bound extraction verdict pack.

use super::DreamerAttemptBinding;
use super::extraction_execution::CheckedExtractionCall;
use crate::EntityId;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, check_extraction_operands_in_txn, evidence_version_for_row,
    extraction_not_served, map_candidate_alias, rebuild_checked_pack,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::{extraction_reader_scope_in_txn, source_version_in_txn};
use crate::verbs::{ExtractionPack, PinnedClaim};

pub(super) use crate::dreamer_consolidation::extraction_pack::{
    bound_branch_error, check_turn_evidence,
};

impl DreamerAttemptBinding {
    /// Checks every pack operand and its rebuilt contract in one live read snapshot.
    pub(super) fn checked_extraction_pack(
        &self,
        pack: &ExtractionPack,
    ) -> MemoryResult<CheckedExtractionCall> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let reader_scope = extraction_reader_scope_in_txn(&memory, &txn, None)?;
        let checked = read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            let (branch, bound) = check_extraction_operands_in_txn(
                &memory,
                &read,
                txn,
                reader_scope.as_ref(),
                self.lease.attempt(),
                &pack.candidates,
                Some((&pack.listed, &pack.priors)),
            )?;
            let branch_subject = branch.subject().unwrap_or_else(|| self.attempt());
            let rebuilt = rebuild_checked_pack(
                pack,
                &bound,
                self.lease.attempt(),
                &branch,
                &ExtractionRebuildContext {
                    memory: &memory,
                    read: &read,
                    txn,
                    operands: &pack.candidates,
                },
                branch_subject,
            )
            .map_err(|error| MemoryError::bad_request(error.message))?;
            check_engine_claim_pins(&read, txn, &pack.listed, &rebuilt.listed)?;
            check_engine_claim_pins(&read, txn, &pack.priors, &rebuilt.priors)?;
            compare_pack_questions(&pack.questions, &rebuilt.questions, &rebuilt.candidate_ids)?;
            let evidence = rebuilt.execution.evidence();
            let rows = read.get_entities_parts_in_txn(txn, evidence)?;
            let versions = evidence
                .iter()
                .zip(rows)
                .map(|(id, row)| {
                    let (_, _, body) = row.ok_or_else(extraction_not_served)?;
                    Ok(evidence_version_for_row(*id, &body))
                })
                .collect::<MemoryResult<Vec<_>>>()?;
            Ok::<_, MemoryError>(CheckedExtractionCall {
                execution: rebuilt.execution,
                versions,
                keys: rebuilt
                    .questions
                    .into_iter()
                    .map(|question| question.key)
                    .collect(),
            })
        })?;
        Ok(checked.value)
    }
}

/// Requires the job's ordered claim references and source pins to equal the engine's set.
fn check_engine_claim_pins(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    offered: &[PinnedClaim],
    expected: &[EntityId],
) -> MemoryResult<()> {
    if offered.len() != expected.len() {
        return Err(MemoryError::bad_request(
            "the extraction pack claim pins differ from the engine's rebuilt set",
        ));
    }
    for (offered, expected) in offered.iter().zip(expected) {
        let Some((version, _)) = source_version_in_txn(read, txn, expected)? else {
            return Err(extraction_not_served());
        };
        if offered.claim != expected.to_hex() || offered.version != version {
            return Err(MemoryError::bad_request(
                "the extraction pack claim pins differ from the engine's rebuilt order or versions",
            ));
        }
    }
    Ok(())
}

/// Compares each rebuilt key and Choice contract in its native question order.
fn compare_pack_questions(
    offered: &[crate::verbs::PackQuestion],
    rebuilt: &[crate::verbs::PackQuestion],
    candidates: &[EntityId],
) -> MemoryResult<()> {
    for index in 0..offered.len().max(rebuilt.len()) {
        let same = match (offered.get(index), rebuilt.get(index)) {
            (Some(offered), Some(rebuilt)) => {
                let options = offered
                    .options
                    .iter()
                    .map(|option| map_candidate_alias(option, candidates))
                    .collect::<crate::Result<Vec<_>>>()
                    .map_err(|error| {
                        MemoryError::bad_request(format!(
                            "extraction question {index} has an invalid option: {error}"
                        ))
                    })?;
                offered.key == rebuilt.key && options == rebuilt.options
            }
            _ => false,
        };
        if !same {
            return Err(MemoryError::bad_request(format!(
                "extraction question {index} differs from its native key or options"
            )));
        }
    }
    Ok(())
}
