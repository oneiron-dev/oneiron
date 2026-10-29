//! The join between a judged amendment's defect share and the native
//! anchored pack outcome it revises (FIX 10148).
//!
//! The native score of an attempt is its anchored pack outcome's credit
//! observation, held in the reliability cell under the sealed credit
//! receipt's key and carrying the stored attempt/outcome context. An
//! amendment judgment charges the attempt, whose pack receipt holds no
//! anchor of its own, so the attempt-lane projection cannot apply the share
//! there. This leaf finds the native observation through that context and
//! states its one effective form: the amendment's loss at its defect share
//! while the amendment stands, the sealed credit's own observation once it
//! is withdrawn. The receipt key, the cell, the anchor and the
//! judge/goal/context provenance never move, and no attempt-keyed row is
//! added beside it.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::evidence::{EVIDENCE, EvidenceRow, cells_for_subject_in_txn};
use crate::learning::{
    EvidenceSource, LearningCell, LearningEvidence, LearningPredicate, Observation,
};
use crate::skill_attribution::{credit_evidence, late_credit_receipt_in_txn};

/// One anchored pack-outcome observation held in `skill`'s reliability
/// cells, with the attempt its stored context names.
pub(super) struct AnchoredRow {
    pub(super) cell: LearningCell,
    pub(super) receipt: String,
    pub(super) attempt: String,
    pub(super) row: EvidenceRow,
}

/// Every anchored pack-outcome observation in `skill`'s reliability cells
/// for `executor`: evidence rows carrying their pack outcome context.
///
/// # Errors
///
/// Storage errors.
pub(super) fn anchored_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: &str,
) -> Result<Vec<AnchoredRow>> {
    let mut rows = Vec::new();
    for held in cells_for_subject_in_txn(vault, txn, skill)? {
        if held.cell.predicate != LearningPredicate::Reliability
            || held.cell.executor.as_deref() != Some(executor)
        {
            continue;
        }
        let digest = held.cell.digest();
        for ((held_digest, receipt), row) in EVIDENCE.scan_from(&vault.store, txn, &digest)? {
            if held_digest != digest {
                continue;
            }
            let Some(context) = &row.pack_attribution else {
                continue;
            };
            rows.push(AnchoredRow {
                cell: held.cell.clone(),
                receipt,
                attempt: context.attempt_receipt.clone(),
                row,
            });
        }
    }
    Ok(rows)
}

/// The evidence `held` should now store, or `None` when the stored row
/// already says it (or its sealed credit is gone, so the native form cannot
/// be restated and the row is left as it stands).
///
/// While an amendment charges the attempt, the observation is that
/// amendment's loss at its defect share, under the native row's anchor and
/// provenance. Otherwise it is the sealed credit's own observation for
/// `skill` — a direct subject's whole run, or a credited share's weighted
/// win — as the pack outcome recorded it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn effective_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    held: &AnchoredRow,
    amended: &BTreeMap<String, f32>,
) -> Result<Option<LearningEvidence>> {
    let row = &held.row;
    let evidence = if let Some(share) = amended.get(&held.attempt) {
        let mut evidence = LearningEvidence::anchored(
            held.receipt.clone(),
            row.at,
            row.anchor,
            Observation::Success(false),
        );
        evidence.weight = f64::from(*share);
        evidence.judge.clone_from(&row.judge);
        evidence.on_judge_model = row.on_judge_model;
        evidence.outcome_label.clone_from(&row.outcome_label);
        evidence.pack_attribution.clone_from(&row.pack_attribution);
        evidence.goal_revision.clone_from(&row.goal_revision);
        evidence
            .measurement_version
            .clone_from(&row.measurement_version);
        evidence
    } else {
        let Some(credit) = late_credit_receipt_in_txn(vault, txn, &held.receipt)? else {
            return Ok(None);
        };
        let Some(fields) = &credit.attribution else {
            return Ok(None);
        };
        let (success, weight) = if credit
            .direct_subjects
            .iter()
            .any(|subject| *subject == Some(*skill))
        {
            (credit.succeeded, 1.0)
        } else if let Some(share) = credit
            .shares
            .iter()
            .find(|share| share.subject == Some(*skill))
        {
            (true, share.weight)
        } else {
            return Ok(None);
        };
        credit_evidence(&credit, fields, success, weight)
    };
    Ok((!matches_row(row, &evidence)).then_some(evidence))
}

/// Whether `evidence` stores exactly the row already held.
fn matches_row(row: &EvidenceRow, evidence: &LearningEvidence) -> bool {
    let same_anchor =
        matches!(evidence.source, EvidenceSource::Anchored(anchor) if anchor == row.anchor);
    same_anchor
        && row.at == evidence.at
        && row.observation == evidence.observation
        && row.weight == evidence.weight
        && row.judge == evidence.judge
        && row.on_judge_model == evidence.on_judge_model
        && row.outcome_label == evidence.outcome_label
        && row.pack_attribution == evidence.pack_attribution
        && row.goal_revision == evidence.goal_revision
        && row.measurement_version == evidence.measurement_version
}
