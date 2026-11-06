//! Claimed tasks through the caller's original source read authority.
//! Receipt tasks retain their existing hydration path. Repair tasks rebuild
//! their source and exact response grader only after a scoped source read.

use std::collections::BTreeSet;

use super::cohort::{cohort_in_txn, exposure_row_in_txn};
use super::repair_case::read_repair_task_in_txn;
use super::replay_input::{hydrate, released_case_in_txn};
use super::{
    DerivationKind, EvalExposureKind, EvalMeasurement, EvalRepairTask, EvalTaskInput,
    MeasurementUnavailable, family_in_txn,
};
use crate::claim::{ClaimReadStatus, ScopedReadReceipt};
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// A released input and, for a response-only Repair task, its in-memory grader.
/// The expected response is never copied to a label or to the candidate input.
#[derive(Debug, Clone)]
pub struct EvalReleasedTask {
    input: EvalTaskInput,
    repair: Option<EvalRepairTask>,
}

impl EvalReleasedTask {
    /// The exact task given to each leg, without the expected response.
    #[must_use]
    pub fn input(&self) -> &EvalTaskInput {
        &self.input
    }

    /// The sourced exact-byte check. Receipt tasks keep their existing scorer
    /// and return `None`; they are never silently scored by this grader.
    #[must_use]
    pub fn grade_response(&self, response: &str) -> Option<bool> {
        self.repair
            .as_ref()
            .map(|task| task.grade_response(response))
    }
}

/// A task and the receipt of its source admission. Kept-attempt tasks do not
/// open a new source lane; their receipt is `None`, not a new read grant.
#[derive(Debug, Clone)]
pub struct EvalTaskRead {
    pub task: std::result::Result<EvalReleasedTask, MeasurementUnavailable>,
    pub receipt: Option<ScopedReadReceipt>,
}

pub(super) fn attempt_read(
    task: std::result::Result<EvalTaskInput, MeasurementUnavailable>,
) -> EvalTaskRead {
    EvalTaskRead {
        task: task.map(|input| EvalReleasedTask {
            input,
            repair: None,
        }),
        receipt: None,
    }
}

/// Repair's three stored exposures must be the actual incumbent, candidate and
/// retest counted by claim_eval_measurement, not repeated IDs or a prefix match.
fn repair_exposures_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &EvalMeasurement,
) -> Result<bool> {
    if row.exposures.iter().collect::<BTreeSet<_>>().len() != 3 {
        return Ok(false);
    }
    let legs = [
        ("incumbent", row.request.incumbent.label()),
        ("candidate", row.request.candidate.label()),
        ("retest", row.request.incumbent.label()),
    ];
    for (id, (leg, pin)) in row.exposures.iter().zip(legs) {
        let Some(exposure) = exposure_row_in_txn(vault, txn, &row.request.cohort, id)? else {
            return Ok(false);
        };
        if exposure.cohort != row.request.cohort
            || exposure.kind != EvalExposureKind::Candidate
            || exposure.consumer != format!("eval_measurement:{}:{leg}", row.digest)
            || exposure.candidate_pin.as_deref() != Some(pin.as_str())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

impl Memory<'_> {
    /// Read one claimed task under this handle's original credential, locality,
    /// destination and room scope. Measurement membership and Coach identity do
    /// not grant source access. Repair's release, case, source and recompilation
    /// are checked on the same final snapshot after the grant clock/body hold.
    /// Receipt/Synthetic tasks retain the original kept-attempt hydration and do
    /// not acquire a new source-read requirement.
    pub fn released_eval_task(
        &self,
        measurement: &[u8; 32],
        case: &EntityId,
    ) -> MemoryResult<EvalTaskRead> {
        let vault = self.vault();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let (_, member) = match released_case_in_txn(vault, &txn, measurement, case)? {
                Ok(released) => released,
                Err(reason) => return Ok(attempt_read(Err(reason))),
            };
            if member.repair_task.is_none() {
                return Ok(attempt_read(hydrate(vault, &txn, member)?));
            }
        }
        // No source bytes were read above. Close the metadata snapshot before
        // read_lane resolves this handle's proof and before persisting its clock.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        lane.persist_grant_clock()?;
        let _bodies = vault.pin_all_result_bodies();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let (row, member) = match released_case_in_txn(vault, &txn, measurement, case)? {
            Ok(released) => released,
            Err(reason) => return Ok(attempt_read(Err(reason))),
        };
        let Some(recipe) = member.repair_task.as_ref() else {
            return Ok(attempt_read(hydrate(vault, &txn, member)?));
        };
        if !repair_exposures_in_txn(vault, &txn, &row)? {
            return Ok(attempt_read(Err(MeasurementUnavailable::NotReleased)));
        }
        let cohort = cohort_in_txn(vault, &txn, &row.request.cohort)?;
        if cohort.retired_at.is_some()
            || cohort.seat != row.request.seat
            || cohort.rubric_revision != row.request.rubric_revision
        {
            return Ok(attempt_read(Err(MeasurementUnavailable::CohortMoved)));
        }
        let family = family_in_txn(vault, &txn, &member.family)?
            .ok_or(Error::CorruptedIndex("Repair case family"))?;
        let source = &recipe.source;
        let id = EntityId::from_hex(&source.claim_ref)?;
        let root = format!("entity:{}", id.to_hex());
        if member.kind != DerivationKind::Repair
            || member.seat != source.seat
            || member.seat != row.request.seat
            || family.seat != member.seat
            || !family.roots.contains(&root)
            || !cohort.families.contains(&family.id)
            || member.receipts.as_slice() != [root]
            || !member.parents.is_empty()
            || member.source_rows.as_deref() != Some([id].as_slice())
        {
            return Err(Error::CorruptedIndex("Repair case recipe binding").into());
        }
        let read = read_repair_task_in_txn(vault, &txn, &lane, recipe)?;
        let task = match read.value {
            None => Err(MeasurementUnavailable::TaskGone),
            Some(task) => {
                let source_hash = blake3::Hash::from_hex(&task.source.source_hash)
                    .map_err(|_| Error::CorruptedIndex("Repair source fingerprint"))?;
                Ok(EvalReleasedTask {
                    input: EvalTaskInput {
                        case: member.id,
                        family: member.family,
                        stratum: member.stratum,
                        kind: "repair.text_response".to_owned(),
                        input: task.response_input().clone(),
                        // The dedicated grader owns the expected response only in memory.
                        labels: Vec::new(),
                        source_hash: *source_hash.as_bytes(),
                        task_hash: task.task_hash,
                        source_rows: Some(task.source_rows.clone()),
                    },
                    repair: Some(task),
                })
            }
        };
        Ok(EvalTaskRead {
            task,
            receipt: Some(read.receipt),
        })
    }
}
