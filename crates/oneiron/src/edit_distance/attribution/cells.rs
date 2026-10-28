//! The one write path into the shared `learning.edit_cost` cells (ARCH-0003
//! #learning-qualifiers, ARCH-0056 §5).
//!
//! Every edit-cost observation this lane makes lands here: an untouched
//! approval on the generating actor, and each attributed share of an amended
//! or rejected receipt on the subject attribution chose. Attribution decides
//! the subject and its share first; this file records what it is handed, one
//! evidence row per receipt per cell, so a replay overwrites rather than
//! counts twice. The cell keeps the untouched / amended / rejected counts
//! beside the mean edit mass.
//!
//! A cell is qualified by `executor` and `consent_scope`, and by `typeRef`
//! when a task placed the run. An actor is its own executor. A skill's
//! executor is the model the drafting run was stamped with, or the
//! unknown-executor key.

use super::taxonomy::{AmendmentClass, AmendmentJudgment};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{
    Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation, TypeRef,
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

/// The `learning.edit_cost` cell of `subject` at `executor` in `scope`, and
/// in task type `type_ref` when one placed the run.
pub(super) fn edit_cost_cell(
    subject: EntityId,
    executor: &str,
    scope: &str,
    type_ref: Option<&TypeRef>,
) -> LearningCell {
    let cell = LearningCell::new(LearningPredicate::EditCost, subject)
        .executor(executor)
        .consent_scope(learning_scope(scope));
    match type_ref {
        Some(type_ref) => cell.type_ref(type_ref.clone()),
        None => cell,
    }
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
/// with nothing to split: it lands on the generating actor's own cell at no
/// edit mass, counted untouched.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub(in crate::edit_distance) fn record_untouched_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    scope: &str,
    receipt: &str,
    at: u64,
) -> Result<()> {
    let cell = edit_cost_cell(actor, &actor.to_hex(), scope, None);
    let evidence = observation(receipt, at, 0.0, 1.0, EditOutcome::Untouched);
    record_in_txn(vault, txn, &cell, &evidence)
}

/// Records each charging share of `judgment` on its subject's cell, and
/// returns the cells charged.
///
/// Only a `skill_defect` share charges the skill and only an
/// `execution_lapse` share charges the actor; every other class charges
/// nobody. Each share weighs its fraction of the receipt at the receipt's
/// edit mass, counted amended, or rejected for a rejection.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub(super) fn charge_judgment_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Vec<LearningCell>> {
    let mut charged = Vec::new();
    for (cell, share) in charged_cells(judgment) {
        let mut evidence = observation(
            &judgment.receipt_id,
            judgment.at,
            f64::from(judgment.d_norm),
            share,
            outcome_of(judgment),
        );
        evidence.judge.clone_from(&judgment.judge);
        evidence.on_judge_model = judgment.on_judge_model();
        record_in_txn(vault, txn, &cell, &evidence)?;
        charged.push(cell);
    }
    Ok(charged)
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

/// Lands `evidence` on `cell`. A subject with no stored entity has nowhere to
/// hold the estimate, and records nothing.
fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
) -> Result<()> {
    if vault
        .store
        .port_entity_record(&*txn, &cell.subject)?
        .is_none()
    {
        return Ok(());
    }
    crate::learning::record_evidence_in_txn(vault, txn, cell, evidence, evidence.at)?;
    Ok(())
}
