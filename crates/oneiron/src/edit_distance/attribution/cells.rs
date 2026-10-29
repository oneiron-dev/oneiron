//! The one write path into the shared `learning.edit_cost` cells (ARCH-0003
//! #learning-qualifiers, ARCH-0056 §5).
//!
//! Every edit-cost observation this lane makes lands here: an untouched
//! approval on the generating actor, and each attributed share of an amended
//! or rejected receipt on the subject attribution chose. Attribution decides
//! the subject and its share first; this file records what it is handed, one
//! evidence row per receipt per cell, so a replay overwrites rather than
//! counts twice. The cell keeps the untouched / amended / rejected counts
//! beside the mean edit mass, and a judged receipt counts its outcome on the
//! generating actor's cell and its skill's even where no share charges them:
//! a count-only row that moves no mean and blames nobody (FIX 9797). Each
//! magnitude carries the engine version it was measured under, and the fold
//! keeps one version per cell (FIX 7822).
//!
//! A cell is qualified by `executor` and `consent_scope`, and by `typeRef`
//! when a task placed the run, in one scope: the project the run counted in
//! or the reviewed claim names, or the vault's (FIX 6038). The consent scope
//! is a qualifier, never the cell's scope. An actor is its own executor. A
//! skill's executor is the model the drafting run was stamped with, or the
//! unknown-executor key. Readers ask the cell ([`edit_cost_for`]); no parallel
//! scalar `actor.edit_cost` / `skill.edit_cost` head is kept (FIX 9797).

use std::collections::{BTreeMap, BTreeSet};

use super::projector::record_target_in_txn;
use super::taxonomy::{AmendmentClass, AmendmentJudgment};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::evidence::{
    cells_for_subject_in_txn, evidence_in_txn, evidence_stands_in_txn, withdraw_evidence_in_txn,
};
use crate::learning::{
    Anchor, Estimate, LearningCell, LearningEvidence, LearningPredicate, Observation,
    PREDICATE_LEARNING_EDIT_COST, TypeRef,
};
use crate::ports::EntityStoreRead;

/// Longest consent scope a learning cell keys verbatim; a longer one keys by
/// its digest.
const MAX_LEARNING_SCOPE_BYTES: usize = 256;

/// The receipt outcome an observation records (ARCH-0055 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditOutcome {
    Untouched,
    Amended,
    Rejected,
}

impl EditOutcome {
    /// The pinned outcome label the cell counts.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Untouched => "untouched",
            Self::Amended => "amended",
            Self::Rejected => "rejected",
        }
    }
}

/// The `learning.edit_cost` cell of `subject` at `executor` in `scope`, in
/// task type `type_ref` when one placed the run, in `project`'s scope (`None`,
/// the vault's).
pub(super) fn edit_cost_cell(
    subject: EntityId,
    executor: &str,
    scope: &str,
    type_ref: Option<&TypeRef>,
    project: Option<EntityId>,
) -> LearningCell {
    let cell = LearningCell::new(LearningPredicate::EditCost, subject)
        .executor(executor)
        .consent_scope(learning_scope(scope))
        .project(project);
    match type_ref {
        Some(type_ref) => cell.type_ref(type_ref.clone()),
        None => cell,
    }
}

/// The `learning.edit_cost` estimate of `subject` at `executor` in `scope`,
/// in task type `type_ref` when one placed the runs, in `project`'s scope
/// (`None`, the vault's): the shared cell's own estimate, `None` while no own
/// run has landed. The scope keys the cell exactly as the writers key it.
///
/// # Errors
///
/// Storage errors; a malformed qualifier.
pub fn edit_cost_for(
    vault: &Vault,
    subject: &EntityId,
    executor: &str,
    scope: &str,
    type_ref: Option<&TypeRef>,
    project: Option<EntityId>,
) -> Result<Option<Estimate>> {
    let cell = edit_cost_cell(*subject, executor, scope, type_ref, project);
    crate::learning::learning_estimate(vault, &cell)
}

/// `scope` as a learning qualifier: verbatim when it fits, its digest when it
/// does not.
pub(super) fn learning_scope(scope: &str) -> String {
    if scope.len() <= MAX_LEARNING_SCOPE_BYTES && !scope.contains('\0') {
        return scope.to_owned();
    }
    format!(
        "scope#{}",
        &crate::entity_id::bytes_to_hex_lower(blake3::hash(scope.as_bytes()).as_bytes())[..32]
    )
}

/// An untouched approval is the decider's verdict on the generator's output
/// with nothing to split: it lands on the generating actor's own cell in the
/// reviewed claim's `project` (`None`, the vault's) at no edit mass, counted
/// untouched.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub(in crate::edit_distance) fn record_untouched_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    scope: &str,
    project: Option<EntityId>,
    receipt: &str,
    at: u64,
) -> Result<()> {
    let cell = edit_cost_cell(actor, &actor.to_hex(), scope, None, project);
    let evidence = observation(receipt, at, 0.0, 1.0, EditOutcome::Untouched);
    record_in_txn(vault, txn, &cell, &evidence, at)
}

/// Lands every row of `judgment` (see [`judgment_rows`]) and returns their
/// cells.
///
/// Each charged subject is recorded in the retraction ledger first, and the
/// receipt's row moves off every other edit-cost cell of that subject, so a
/// re-judgment onto another executor, scope or task type never counts in two
/// cells. A row that already stands as written is left alone.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub(super) fn charge_judgment_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Vec<LearningCell>> {
    let rows = judgment_rows(judgment);
    let subjects: BTreeSet<EntityId> = rows.iter().map(|(cell, _)| cell.subject).collect();
    for subject in &subjects {
        record_target_in_txn(
            vault,
            txn,
            PREDICATE_LEARNING_EDIT_COST,
            subject,
            &judgment.receipt_id,
        )?;
        settle_receipt_rows_in_txn(
            vault,
            txn,
            subject,
            &judgment.receipt_id,
            &rows,
            judgment.at,
        )?;
    }
    // Charged and count-only rows both reach the worsening check, so a
    // rejection that charges nobody still extends its subject's run.
    let cells: Vec<LearningCell> = rows.into_iter().map(|(cell, _)| cell).collect();
    super::worsening::observe_charge_in_txn(vault, txn, judgment, &cells);
    Ok(cells)
}

/// Every row `judgment` lands, each on its cell.
///
/// Only a `skill_defect` share charges the skill and only an
/// `execution_lapse` share charges the actor; every other class charges
/// nobody. Each charging share weighs its fraction of the receipt at the
/// receipt's edit mass, measured under its engine version, counted amended,
/// or rejected for a rejection. The generating actor's own cell (where its
/// untouched approvals land) and the skill's cell at the drafting executor
/// count the outcome too: where no share charges that cell, a count-only row
/// does, with no mass and no judge.
pub(super) fn judgment_rows(judgment: &AmendmentJudgment) -> Vec<(LearningCell, LearningEvidence)> {
    let outcome = outcome_of(judgment);
    let mut rows: Vec<(LearningCell, LearningEvidence)> = charged_cells(judgment)
        .into_iter()
        .map(|(cell, share)| {
            let mut evidence = observation(
                &judgment.receipt_id,
                judgment.at,
                f64::from(judgment.d_norm),
                share,
                outcome,
            );
            evidence.judge.clone_from(&judgment.judge);
            evidence.on_judge_model = judgment.on_judge_model();
            evidence.measurement_version = Some(judgment.engine_ver.clone());
            (cell, evidence)
        })
        .collect();
    let counted = [
        judgment.actor.map(|actor| {
            edit_cost_cell(
                actor,
                &actor.to_hex(),
                &judgment.scope,
                None,
                judgment.project,
            )
        }),
        judgment.skill.map(|skill| {
            edit_cost_cell(
                skill,
                judgment.executor_key(),
                &judgment.scope,
                judgment.type_ref.as_ref(),
                judgment.project,
            )
        }),
    ];
    for cell in counted.into_iter().flatten() {
        if rows.iter().any(|(charged, _)| *charged == cell) {
            continue;
        }
        let evidence = LearningEvidence::anchored(
            judgment.receipt_id.as_str(),
            judgment.at,
            Anchor::OwnerVerdict,
            Observation::CountOnly(outcome.as_str().to_owned()),
        );
        rows.push((cell, evidence));
    }
    rows
}

/// Whether `judgment` charges `subject` any share.
pub(super) fn charges_subject(judgment: &AmendmentJudgment, subject: &EntityId) -> bool {
    charged_cells(judgment)
        .iter()
        .any(|(cell, _)| cell.subject == *subject)
}

/// Brings `receipt`'s rows on `subject`'s edit-cost cells in line with
/// `rows`: the receipt leaves every cell of `subject` that `rows` does not
/// name, and each of `subject`'s rows that does not stand as written lands
/// again, projected at `now`.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub(super) fn settle_receipt_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    receipt: &str,
    rows: &[(LearningCell, LearningEvidence)],
    now: u64,
) -> Result<()> {
    let own: Vec<&(LearningCell, LearningEvidence)> = rows
        .iter()
        .filter(|(cell, _)| cell.subject == *subject)
        .collect();
    let keep: Vec<&LearningCell> = own.iter().map(|(cell, _)| cell).collect();
    withdraw_receipt_in_txn(vault, txn, subject, receipt, &keep, now)?;
    for (cell, evidence) in own {
        if !evidence_stands_in_txn(vault, &*txn, cell, evidence)? {
            record_in_txn(vault, txn, cell, evidence, now)?;
        }
    }
    Ok(())
}

/// Whether a receipt's rows on `subject`'s edit-cost cells are exactly
/// `rows`' rows for `subject`, read in `txn`: each stands as written, and
/// `holders`, the cells of `subject` that hold the receipt (see
/// [`receipt_cells_in_txn`]), are all among them. A subject with no stored
/// entity holds nothing, so its rows stand.
///
/// # Errors
///
/// Storage errors.
pub(super) fn receipt_rows_stand_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    rows: &[(LearningCell, LearningEvidence)],
    holders: &[LearningCell],
) -> Result<bool> {
    if !holds_estimates_in_txn(vault, txn, subject)? {
        return Ok(true);
    }
    for (cell, evidence) in rows.iter().filter(|(cell, _)| cell.subject == *subject) {
        if !evidence_stands_in_txn(vault, txn, cell, evidence)? {
            return Ok(false);
        }
    }
    Ok(holders
        .iter()
        .all(|held| rows.iter().any(|(cell, _)| cell == held)))
}

/// The edit-cost cells of `subject` that hold each receipt, read in `txn`
/// with one pass over the subject's cells.
///
/// # Errors
///
/// Storage errors.
pub(super) fn receipt_cells_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<BTreeMap<String, Vec<LearningCell>>> {
    let mut held: BTreeMap<String, Vec<LearningCell>> = BTreeMap::new();
    for row in cells_for_subject_in_txn(vault, txn, subject)? {
        if row.cell.predicate != LearningPredicate::EditCost {
            continue;
        }
        for (receipt, _) in evidence_in_txn(vault, txn, &row.cell.digest())? {
            held.entry(receipt).or_default().push(row.cell.clone());
        }
    }
    Ok(held)
}

/// Withdraws `receipt`'s evidence from every `learning.edit_cost` cell of
/// `subject` but those in `keep`, reprojecting each cell it leaves at `now`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn withdraw_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    receipt: &str,
    keep: &[&LearningCell],
    now: u64,
) -> Result<()> {
    for row in cells_for_subject_in_txn(vault, &*txn, subject)? {
        if row.cell.predicate != LearningPredicate::EditCost || keep.contains(&&row.cell) {
            continue;
        }
        withdraw_evidence_in_txn(vault, txn, &row.cell, receipt, now)?;
    }
    Ok(())
}

/// Each cell `judgment` charges, with the share it charges there.
fn charged_cells(judgment: &AmendmentJudgment) -> Vec<(LearningCell, f64)> {
    judgment
        .split
        .iter()
        .filter(|share| share.share > 0.0)
        .filter_map(|share| {
            let subject = share.subject?;
            let executor = match share.class {
                // An actor is its own executor.
                AmendmentClass::ExecutionLapse => subject.to_hex(),
                AmendmentClass::SkillDefect => judgment.executor_key().to_owned(),
                AmendmentClass::Discovery
                | AmendmentClass::Environment
                | AmendmentClass::PreferenceShift
                | AmendmentClass::Unclear => return None,
            };
            let cell = edit_cost_cell(
                subject,
                &executor,
                &judgment.scope,
                judgment.type_ref.as_ref(),
                judgment.project,
            );
            Some((cell, f64::from(share.share)))
        })
        .collect()
}

/// The outcome a judged receipt records.
const fn outcome_of(judgment: &AmendmentJudgment) -> EditOutcome {
    if judgment.rejected {
        EditOutcome::Rejected
    } else {
        EditOutcome::Amended
    }
}

/// One owner-verdict observation of `magnitude` at `weight`.
fn observation(
    receipt: &str,
    at: u64,
    magnitude: f64,
    weight: f64,
    outcome: EditOutcome,
) -> LearningEvidence {
    let mut evidence = LearningEvidence::anchored(
        receipt,
        at,
        Anchor::OwnerVerdict,
        Observation::Magnitude(magnitude),
    );
    evidence.weight = weight;
    evidence.outcome_label = Some(outcome.as_str().to_owned());
    evidence
}

/// Whether `subject` is a stored entity, the only kind that can hold an
/// estimate.
fn holds_estimates_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<bool> {
    Ok(vault.store.port_entity_record(txn, subject)?.is_some())
}

/// Lands `evidence` on `cell`, projecting the cell at `now`. A subject with
/// no stored entity has nowhere to hold the estimate, and records nothing.
fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    now: u64,
) -> Result<()> {
    if !holds_estimates_in_txn(vault, &*txn, &cell.subject)? {
        return Ok(());
    }
    crate::learning::record_evidence_in_txn(vault, txn, cell, evidence, now)?;
    Ok(())
}
