//! The persistent-failure trigger (ARCH-0056 §5 "Persistent failure → the
//! triage packet"; FIX 7825).
//!
//! Every charge that lands a share on a subject's `learning.edit_cost` cell is
//! checked here, in a savepoint of the charging write, for the three
//! worsening signals canon names per subject and scope. Each is read from
//! receipts and the measured cells alone:
//!
//! - **edit-cost climbing**: the cell's own head against the head it
//!   superseded, climbing only when the mean rose by more than the spread the
//!   cell held before. No slope is fitted.
//! - **a rejection run**: the subject's newest outcomes in the scope, across
//!   every executor and task type, rejected [`REJECTION_RUN_LENGTH`] times in
//!   a row. An untouched or amended outcome ends the run.
//! - **a reliability floor-crossing**: an open quarantine proposal on a
//!   charged skill, the row the reliability floor contract keeps of a
//!   downward crossing until the skill recovers.
//!
//! A signal that fires mints, or brings up to date, the subject's one
//! escalation for that scope and signal ([`super::triage`]). It is a record
//! and an inbox item: nothing is blocked, held or refused, no local
//! mitigation waits on it, and a check that fails leaves the charge as it
//! landed.

use super::taxonomy::{AmendmentClass, AmendmentJudgment};
use super::triage::{TriageSubject, WorseningSignal, escalate_in_txn, packet_in_txn};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::project::{StoredEstimateClaim, active_heads_in_txn};
use crate::learning::{
    ESTIMATOR_VERSION, Estimate, EstimateValue, LearningCell, LearningPredicate,
};
use crate::ports::{EdgeDirection, EdgeStore};
use crate::skill_reliability::open_floor_crossings_in_txn;

/// Rejections in a row, in one scope, that make a run. Canon names rejection
/// runs and pins no length; three is the manifest's other recurrence count
/// (`miner_recurrence_receipts`, `escalation_standing_rulings`).
const REJECTION_RUN_LENGTH: usize = 3;

/// The outcome label a rejection's charge records on its cell (ARCH-0055 §7).
const REJECTED_OUTCOME: &str = "rejected";

/// Checks each cell `judgment` charged for a worsening signal, and escalates
/// each one that fires, in a savepoint of the charging write: an optional
/// capture that never fails the charge it rides.
pub(super) fn observe_charge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
    charged: &[LearningCell],
) {
    if charged.is_empty() {
        return;
    }
    let landed = vault
        .store
        .env
        .nested_write_txn(txn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            for cell in charged {
                escalate_cell_in_txn(vault, &mut savepoint, judgment, cell)?;
            }
            Ok(savepoint.commit()?)
        });
    if let Err(error) = landed {
        tracing::warn!(
            kind = ?error.kind(),
            receipt = %judgment.receipt_id,
            "a worsening check did not land; the charge stands"
        );
    }
}

/// Every signal `cell`'s subject shows in `judgment`'s scope, each escalated.
fn escalate_cell_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
    cell: &LearningCell,
) -> Result<()> {
    let Some(kind) = subject_kind(judgment, &cell.subject) else {
        return Ok(());
    };
    let mut fired = Vec::new();
    fired.extend(climbing_in_txn(vault, txn, cell)?);
    if let Some(scope) = cell.consent_scope.as_deref() {
        fired.extend(rejection_run_in_txn(vault, txn, &cell.subject, scope)?);
    }
    if kind == TriageSubject::Skill {
        fired.extend(floor_crossing_in_txn(vault, txn, &cell.subject)?);
    }
    for signal in fired {
        let packet = packet_in_txn(vault, txn, judgment, cell.subject, kind, signal)?;
        escalate_in_txn(vault, txn, &packet)?;
    }
    Ok(())
}

/// What `subject` is to `judgment`: the skill a `skill_defect` share charges
/// or the actor an `execution_lapse` share charges.
fn subject_kind(judgment: &AmendmentJudgment, subject: &EntityId) -> Option<TriageSubject> {
    judgment
        .split
        .iter()
        .filter(|share| share.subject == Some(*subject))
        .find_map(|share| match share.class {
            AmendmentClass::SkillDefect => Some(TriageSubject::Skill),
            AmendmentClass::ExecutionLapse => Some(TriageSubject::Actor),
            AmendmentClass::Discovery
            | AmendmentClass::Environment
            | AmendmentClass::PreferenceShift
            | AmendmentClass::Unclear => None,
        })
}

/// The cell's own head against the head it superseded: climbing when the
/// mean rose past the spread the earlier head held.
fn climbing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Option<WorseningSignal>> {
    let Some((head, current)) = richest_head_in_txn(vault, txn, cell)? else {
        return Ok(None);
    };
    let mut previous: Option<(EntityId, Estimate)> = None;
    for edge in vault.port_edge_neighbors(
        txn,
        &head,
        EdgeDirection::Out,
        Some(EdgeKind::Supersedes),
        usize::MAX,
    )? {
        let Some(estimate) = estimate_of_in_txn(vault, txn, &edge.target, cell)? else {
            continue;
        };
        if previous
            .as_ref()
            .is_none_or(|(_, held)| estimate.runs > held.runs)
        {
            previous = Some((edge.target, estimate));
        }
    }
    let Some((previous_head, previous)) = previous else {
        return Ok(None);
    };
    let (
        EstimateValue::Mean {
            mean: previous_mean,
            spread: previous_spread,
        },
        EstimateValue::Mean {
            mean: current_mean,
            spread: current_spread,
        },
    ) = (previous.value, current.value)
    else {
        return Ok(None);
    };
    if current_mean - previous_mean <= previous_spread {
        return Ok(None);
    }
    Ok(Some(WorseningSignal::EditCostClimbing {
        previous_head: previous_head.to_hex(),
        previous_mean,
        previous_spread,
        current_head: head.to_hex(),
        current_mean,
        current_spread,
    }))
}

/// The cell's active head with the most own runs, and its estimate.
fn richest_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Option<(EntityId, Estimate)>> {
    let mut richest: Option<(EntityId, Estimate)> = None;
    for (head, _, _) in active_heads_in_txn(vault, txn, cell)? {
        let Some(estimate) = estimate_of_in_txn(vault, txn, &head, cell)? else {
            continue;
        };
        if richest
            .as_ref()
            .is_none_or(|(_, held)| estimate.runs > held.runs)
        {
            richest = Some((head, estimate));
        }
    }
    Ok(richest)
}

/// The estimate claim `id` holds for `cell` under this estimator, if it holds
/// one.
fn estimate_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    cell: &LearningCell,
) -> Result<Option<Estimate>> {
    let Some(body) = vault.get_claim_in_txn(txn, id)? else {
        return Ok(None);
    };
    Ok(StoredEstimateClaim::from_value(&body.value)
        .ok()
        .filter(|stored| stored.cell == *cell && stored.estimate.ver == ESTIMATOR_VERSION)
        .map(|stored| stored.estimate))
}

/// The run of rejections `subject`'s newest outcomes in `scope` end on, over
/// every `learning.edit_cost` cell it holds there, when it is long enough.
fn rejection_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    scope: &str,
) -> Result<Option<WorseningSignal>> {
    let mut outcomes = Vec::new();
    for row in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, subject)? {
        if row.cell.predicate != LearningPredicate::EditCost
            || row.cell.consent_scope.as_deref() != Some(scope)
        {
            continue;
        }
        for (receipt, evidence) in
            crate::learning::evidence::evidence_in_txn(vault, txn, &row.cell.digest())?
        {
            let rejected = evidence.outcome_label.as_deref() == Some(REJECTED_OUTCOME);
            outcomes.push((evidence.at, receipt, rejected));
        }
    }
    outcomes.sort();
    let run: Vec<&String> = outcomes
        .iter()
        .rev()
        .take_while(|(_, _, rejected)| *rejected)
        .map(|(_, receipt, _)| receipt)
        .collect();
    let Some(newest) = run.first() else {
        return Ok(None);
    };
    if run.len() < REJECTION_RUN_LENGTH {
        return Ok(None);
    }
    Ok(Some(WorseningSignal::RejectionRun {
        length: u32::try_from(run.len()).unwrap_or(u32::MAX),
        newest: (*newest).clone(),
    }))
}

/// The newest floor crossing still open on `skill`: one per escalation, so
/// two executors' open crossings never take turns rewriting it.
fn floor_crossing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<WorseningSignal>> {
    Ok(open_floor_crossings_in_txn(vault, txn, skill)?
        .into_iter()
        .max_by_key(|crossing| (crossing.at, crossing.proposal))
        .map(|crossing| WorseningSignal::ReliabilityFloor {
            proposal: crossing.proposal.to_hex(),
            executor: crossing.executor,
            lower_bound: crossing.lower_bound,
            floor: crossing.floor,
            crossed_at: crossing.at,
        }))
}
