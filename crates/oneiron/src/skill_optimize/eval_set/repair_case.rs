//! Owner-requested Repair cases. Source admission and the case write share one
//! writer; the ledger stores only a source recipe and its complete task digest.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::repair_task::compile_repair_task;
use super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalCaseDraft, EvalRepairTaskSource, FamilyPurpose,
    assign_family_in_txn, put_case_in_txn, record_case_in_txn, rows_in_txn,
};
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadReceipt};
use crate::consent::AuthenticatedOwner;
use crate::ingest::{AgUiFileReadInput, project_ag_ui_file};
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Error};

/// Frozen reconstruction recipe. Neither the task input nor its expected answer
/// is copied into the case ledger; every use must read the admitted source again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairCaseRecipe {
    pub source: EvalRepairTaskSource,
    pub task_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairCaseRequest {
    pub recipe: EvalRepairCaseRecipe,
    pub purpose: FamilyPurpose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRepairCaseRead {
    /// Missing or withheld sources author no family, case or label.
    pub case: Option<EvalCase>,
    pub receipt: ScopedReadReceipt,
}

impl Memory<'_> {
    /// Record an explicit owner-requested case from this handle's ordinary scoped
    /// read. Owner proof permits the eval write, never a broader source read.
    /// Family purpose is assigned before the case, in the same transaction.
    pub fn record_eval_repair_case(
        &self,
        owner: &AuthenticatedOwner,
        input: &EvalRepairCaseRequest,
    ) -> MemoryResult<EvalRepairCaseRead> {
        let source = &input.recipe.source;
        let id = EntityId::from_hex(&source.claim_ref)?;
        let source_pin = AgUiFileReadInput {
            claim_ref: source.claim_ref.clone(),
            source_hash: source.source_hash.clone(),
        };
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        lane.persist_grant_clock()?;
        let vault = self.vault();
        let _bodies = vault.pin_all_result_bodies();
        let now = vault.now_recorded_at();
        Ok(vault.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(vault, txn)?;
            let read =
                lane.read_projected_in_txn(txn, &[PointRead::id(id)], None, |snapshot, rows| {
                    project_ag_ui_file(vault, snapshot, id, &source_pin, rows)
                })?;
            let Some((view, source_at)) = read.value else {
                return Ok(EvalRepairCaseRead {
                    case: None,
                    receipt: read.receipt,
                });
            };
            if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
                return Err(Error::InvalidClaimBody("Repair source was erased"));
            }
            let task = compile_repair_task(&view, source)?;
            let recipe = EvalRepairCaseRecipe {
                source: task.source.clone(),
                task_hash: task.task_hash,
            };
            if recipe.task_hash != input.recipe.task_hash {
                return Err(Error::InvalidClaimBody("Repair task digest changed"));
            }
            let root = task.family_root();
            let family = assign_family_in_txn(
                vault,
                txn,
                &task.source.seat,
                &BTreeSet::from([root.clone()]),
                input.purpose,
                now,
            )?;
            for case in rows_in_txn::<EvalCase>(vault, txn, CASE_PREFIX)? {
                if case.family == family.id
                    && case.seat == task.source.seat
                    && case.kind == DerivationKind::Repair
                    && case.repair_task.as_ref() == Some(&recipe)
                    && case.receipts.len() == 1
                    && case.receipts.first() == Some(&root)
                    && case.parents.is_empty()
                    && case.source_rows.as_deref() == Some(task.source_rows.as_slice())
                {
                    return Ok(EvalRepairCaseRead {
                        case: Some(case),
                        receipt: read.receipt,
                    });
                }
            }
            let mut case = record_case_in_txn(
                vault,
                txn,
                &EvalCaseDraft {
                    seat: task.source.seat,
                    kind: DerivationKind::Repair,
                    receipts: vec![root],
                    parents: Vec::new(),
                    stratum: None,
                    draw_probability: None,
                    // The admitted claim's capture time, not an app event timestamp.
                    source_at,
                },
                Some(&task.source_rows),
                now,
            )?;
            case.repair_task = Some(recipe.clone());
            put_case_in_txn(vault, txn, &mut case)?;
            if case.repair_task.as_ref() != Some(&recipe)
                || case.source_rows.as_deref() != Some(task.source_rows.as_slice())
            {
                return Err(Error::InvalidClaimBody(
                    "Repair recipe changed during admission",
                ));
            }
            Ok(EvalRepairCaseRead {
                case: Some(case),
                receipt: read.receipt,
            })
        })?)
    }
}
