//! The persistent-failure trigger (ARCH-0056 §5 "Persistent failure → the
//! triage packet"; FIX 7825).
//!
//! Every outcome that lands on a subject's `learning.edit_cost` cell is
//! checked here, in a savepoint of the write that lands it, for the three
//! worsening signals canon names per subject and scope. Each is read from
//! receipts and the measured cells alone:
//!
//! - **edit-cost climbing**: the cell's own head against the head it
//!   superseded, climbing only when the mean rose by more than the spread the
//!   cell held before. No slope is fitted.
//! - **a rejection run**: the subject's newest outcomes in the scope, across
//!   every executor and task type, rejected [`REJECTION_RUN_LENGTH`] times in
//!   a row, charged or count-only. An untouched or amended outcome ends the
//!   run.
//! - **a reliability floor-crossing**: an open quarantine proposal on a
//!   charged skill, the row the reliability floor contract keeps of a
//!   downward crossing until the skill recovers.
//!
//! A charge checks all three ([`observe_charge_in_txn`]); an outcome that
//! charges nobody checks the run alone ([`observe_rejection_in_txn`]). A
//! signal that fires mints, or brings up to date, the subject's one
//! escalation for that scope and signal ([`super::triage`]). It is a record
//! and an inbox item: nothing is blocked, held or refused, no local
//! mitigation waits on it, and a check that fails leaves the outcome as it
//! landed.

use std::collections::BTreeSet;

use super::cells::learning_scope;
use super::taxonomy::{AmendmentClass, AmendmentJudgment};
use super::triage::{TriageSubject, WorseningSignal, escalate_in_txn, packet_in_txn};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::evidence::EvidenceRow;
use crate::learning::project::{StoredEstimateClaim, active_heads_in_txn};
use crate::learning::{
    ESTIMATOR_VERSION, Estimate, EstimateValue, LearningCell, LearningPredicate, Observation,
};
use crate::ports::{EdgeDirection, EdgeStore};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_reliability::open_floor_crossings_in_txn;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Rejections in a row, in one scope, that make a run. Canon names rejection
/// runs and pins no length; three is the manifest's other recurrence count
/// (`miner_recurrence_receipts`, `escalation_standing_rulings`).
const REJECTION_RUN_LENGTH: usize = 3;

/// The outcome labels a cell row records (ARCH-0055 §7).
const AMENDED_OUTCOME: &str = "amended";
const REJECTED_OUTCOME: &str = "rejected";

/// One outcome a subject's cell holds: when it landed, its receipt, and its
/// label.
pub(super) struct CellOutcome {
    pub(super) at: u64,
    pub(super) receipt: String,
    label: Option<String>,
}

impl CellOutcome {
    /// Whether the decider amended or rejected it.
    pub(super) fn failed(&self) -> bool {
        matches!(
            self.label.as_deref(),
            Some(AMENDED_OUTCOME | REJECTED_OUTCOME)
        )
    }

    fn rejected(&self) -> bool {
        self.label.as_deref() == Some(REJECTED_OUTCOME)
    }
}

/// Checks each cell `judgment` charged for a worsening signal, and escalates
/// each one that fires: climbing and the floor here, the run through
/// [`observe_rejection_in_txn`]. Each check runs in a savepoint of the
/// charging write and never fails the charge it rides.
pub(super) fn observe_charge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
    charged: &[LearningCell],
) {
    if charged.is_empty() {
        return;
    }
    in_savepoint(vault, txn, &judgment.receipt_id, |savepoint| {
        for cell in charged {
            escalate_cell_in_txn(vault, savepoint, judgment, cell)?;
        }
        Ok(())
    });
    let subjects: BTreeSet<EntityId> = charged.iter().map(|cell| cell.subject).collect();
    for subject in &subjects {
        observe_rejection_in_txn(vault, txn, subject, &judgment.scope, &judgment.receipt_id);
    }
}

/// Checks `subject`'s rejection run in `scope` once the outcome on receipt
/// `trigger` has landed on one of its `learning.edit_cost` cells, and
/// escalates the run when it is long enough. `scope` is the receipt's scope
/// as its judgment keeps it. In a savepoint of the caller's write, which it
/// never fails: the entry both the charge and an outcome that charges nobody
/// call.
pub(crate) fn observe_rejection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    scope: &str,
    trigger: &str,
) {
    in_savepoint(vault, txn, trigger, |savepoint| {
        escalate_run_in_txn(vault, savepoint, subject, scope, trigger)
    });
}

/// Runs `check` in a savepoint of `txn` that commits only when all of it
/// lands; an error drops the savepoint alone and logs one WARN.
fn in_savepoint(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    check: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) {
    let landed = vault
        .store
        .env
        .nested_write_txn(txn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            check(&mut savepoint)?;
            Ok(savepoint.commit()?)
        });
    if let Err(error) = landed {
        tracing::warn!(
            kind = ?error.kind(),
            receipt,
            "a worsening check did not land; the outcome stands"
        );
    }
}

/// The edit-cost climb and the floor crossing `cell`'s subject shows, each
/// escalated in `judgment`'s scope.
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
    if kind == TriageSubject::Skill {
        fired.extend(floor_crossing_in_txn(vault, txn, &cell.subject)?);
    }
    for signal in fired {
        let packet = packet_in_txn(
            vault,
            txn,
            cell.subject,
            kind,
            &judgment.scope,
            judgment.at,
            signal,
        )?;
        escalate_in_txn(vault, txn, &packet)?;
    }
    Ok(())
}

/// Escalates `subject`'s rejection run in `scope` when `trigger` is in it and
/// it is long enough.
fn escalate_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    scope: &str,
    trigger: &str,
) -> Result<()> {
    let mut outcomes = outcomes_in_txn(vault, txn, subject, scope)?;
    outcomes.sort_by(|a, b| (a.at, &a.receipt).cmp(&(b.at, &b.receipt)));
    let run: Vec<&CellOutcome> = outcomes
        .iter()
        .rev()
        .take_while(|outcome| outcome.rejected())
        .collect();
    let Some(newest) = run.first() else {
        return Ok(());
    };
    // A check prompted by an outcome outside the run says nothing new.
    if run.len() < REJECTION_RUN_LENGTH || !run.iter().any(|outcome| outcome.receipt == trigger) {
        return Ok(());
    }
    let kind = match live_entity_row_in_txn(&vault.store, txn, subject)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_SKILL => {
            TriageSubject::Skill
        }
        LiveEntityRow::Live { .. } => TriageSubject::Actor,
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => return Ok(()),
    };
    let signal = WorseningSignal::RejectionRun {
        length: u32::try_from(run.len()).unwrap_or(u32::MAX),
        newest: newest.receipt.clone(),
    };
    let packet = packet_in_txn(vault, txn, *subject, kind, scope, newest.at, signal)?;
    escalate_in_txn(vault, txn, &packet)
}

/// Every outcome `subject`'s `learning.edit_cost` cells hold in `scope`, at
/// any executor and task type, charged or count-only. `scope` is the
/// receipt's scope as its judgment keeps it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn outcomes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    scope: &str,
) -> Result<Vec<CellOutcome>> {
    let scope = learning_scope(scope);
    let mut outcomes = Vec::new();
    for row in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, subject)? {
        if row.cell.predicate != LearningPredicate::EditCost
            || row.cell.consent_scope.as_deref() != Some(scope.as_str())
        {
            continue;
        }
        for (receipt, evidence) in
            crate::learning::evidence::evidence_in_txn(vault, txn, &row.cell.digest())?
        {
            outcomes.push(CellOutcome {
                at: evidence.at,
                receipt,
                label: outcome_label(evidence),
            });
        }
    }
    Ok(outcomes)
}

/// A row's outcome label: the one a measured row keeps beside its
/// magnitude, or a count-only row's category.
fn outcome_label(row: EvidenceRow) -> Option<String> {
    match (row.outcome_label, row.observation) {
        (Some(label), _) | (None, Observation::Category(label)) => Some(label),
        (None, Observation::Success(_) | Observation::Magnitude(_)) => None,
    }
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
