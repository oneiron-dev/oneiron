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
//! while the amendment stands, the credit's standing observation (its
//! latest adjustment included) once it is withdrawn. The receipt key, the cell, the anchor and the
//! judge/goal/context provenance never move, and no attempt-keyed row is
//! added beside it. The flip is read per executor arm, like the attempt
//! lane's own outcomes: it assumes the attempt's stamped executor is the
//! arm its amendment charges (the pack stamp's validity rule), so a
//! callable invoked under other executors would need the scan widened to
//! every invoker arm.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::evidence::{EVIDENCE, EvidenceRow, cells_for_subject_in_txn};
use crate::learning::{
    EvidenceSource, LearningCell, LearningEvidence, LearningPredicate, Observation,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_attribution::{
    LateCreditReceipt, late_credit_receipt_in_txn, standing_credit_observation_in_txn,
};

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

/// What one anchored row should now store under its stable key.
pub(super) enum AnchoredEffect {
    /// The stored row already says it; write nothing.
    Stand,
    /// Replace the stored row with this evidence.
    Record(LearningEvidence),
    /// The standing credit credits this subject nothing (its row is a
    /// flipped loss the credit never carried): withdraw the row.
    Withdraw,
}

/// The effect `held` should now take. While an amendment charges the
/// attempt, the effective observation is that amendment's loss at its
/// defect share. Otherwise it is the credit's standing observation — the
/// latest credit adjustment's mass, not only the sealed projection's — so
/// a withdrawn amendment restores exactly what the credit side last wrote.
/// The sealed credit gone, or erased to no attribution, leaves the row as
/// it stands rather than guessed at. Either restatement keeps the stored
/// row's receipt key, time, anchor, judge, goal revision and pack context;
/// only the observation and its weight ever move.
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
) -> Result<AnchoredEffect> {
    let row = &held.row;
    if let Some(share) = amended.get(&held.attempt) {
        let evidence = restated(held, false, f64::from(*share));
        return Ok(if matches_row(row, &evidence) {
            AnchoredEffect::Stand
        } else {
            AnchoredEffect::Record(evidence)
        });
    }
    let Some(credit) = late_credit_receipt_in_txn(vault, txn, &held.receipt)? else {
        return Ok(AnchoredEffect::Stand);
    };
    if credit.attribution.is_none() {
        return Ok(AnchoredEffect::Stand);
    }
    match standing_credit_observation_in_txn(vault, txn, &credit, skill)? {
        Some((success, weight)) => {
            let evidence = restated(held, success, weight);
            Ok(if matches_row(row, &evidence) {
                AnchoredEffect::Stand
            } else {
                AnchoredEffect::Record(evidence)
            })
        }
        // Only a credited win's masses can move to nothing; a failed
        // credit that never named this subject is not this leaf's row to
        // judge.
        None if credit.succeeded => Ok(AnchoredEffect::Withdraw),
        None => Ok(AnchoredEffect::Stand),
    }
}

/// `held`'s stored row restated at one observation and weight, keeping
/// every other field the native credit row froze.
fn restated(held: &AnchoredRow, success: bool, weight: f64) -> LearningEvidence {
    let row = &held.row;
    let mut evidence = LearningEvidence::anchored(
        held.receipt.clone(),
        row.at,
        row.anchor,
        Observation::Success(success),
    );
    evidence.weight = weight;
    evidence.judge.clone_from(&row.judge);
    evidence.on_judge_model = row.on_judge_model;
    evidence.outcome_label.clone_from(&row.outcome_label);
    evidence.pack_attribution.clone_from(&row.pack_attribution);
    evidence.goal_revision.clone_from(&row.goal_revision);
    evidence
        .measurement_version
        .clone_from(&row.measurement_version);
    evidence
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

/// Mint the flipped loss for an amendment whose attempt has no anchored row
/// to flip and no desired row (FIX 11676): the sealed credit's context gives
/// the cell and provenance, the amendment's defect share the loss weight.
/// `None` when no sealed credit for `attempt` names `skill` on this arm, or
/// its attribution is gone. The receipt key is the credit's id, so re-minting
/// replaces in place.
///
/// # Errors
///
/// Storage errors.
pub(super) fn mint_flipped_from_credit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: &str,
    attempt: &str,
    share: f32,
) -> Result<Option<(LearningCell, LearningEvidence)>> {
    const CREDIT: SideTable<String, LateCreditReceipt, Named> =
        SideTable::new(&side_table::SKILL_ATTRIBUTION_LATE_CREDIT);
    let mut candidates = Vec::new();
    for (_, credit) in CREDIT.scan(&vault.store, txn)? {
        if credit.attempt_receipt != attempt {
            continue;
        }
        let Some(fields) = &credit.attribution else {
            continue;
        };
        if fields.executor != executor {
            continue;
        }
        let names = credit.direct_subjects.contains(&Some(*skill))
            || credit
                .shares
                .iter()
                .any(|share| share.subject == Some(*skill));
        if !names {
            continue;
        }
        candidates.push(credit);
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    let credit = if candidates.len() == 1 {
        let Some(credit) = candidates.pop() else {
            return Ok(None);
        };
        credit
    } else {
        let axis = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
            .and_then(|receipt| receipt.fields.get("axis").cloned())
            .unwrap_or_else(|| crate::skill_reliability::SKILL_OUTCOME_AXIS.to_owned());
        match candidates
            .iter()
            .position(|candidate| candidate.axis == axis)
        {
            Some(index) => candidates.swap_remove(index),
            None => {
                let Some(credit) = candidates.into_iter().next() else {
                    return Ok(None);
                };
                credit
            }
        }
    };
    let Some(fields) = credit.attribution.clone() else {
        return Ok(None);
    };
    let cell = LearningCell::new(LearningPredicate::Reliability, *skill)
        .executor(fields.executor.clone())
        .type_ref(fields.type_ref.clone())
        .axis(credit.axis.clone())
        .project(fields.project);
    let mut evidence = LearningEvidence::anchored(
        credit.receipt_id.clone(),
        credit.at,
        credit.anchor,
        Observation::Success(false),
    );
    evidence.weight = f64::from(share);
    evidence.judge.clone_from(&fields.judge);
    evidence.on_judge_model = fields.judge.as_deref() == Some(fields.executor.as_str());
    evidence.pack_attribution = Some(crate::receipt::PackLearningContext {
        attempt_receipt: credit.attempt_receipt.clone(),
        outcome_receipt: credit.outcome_receipt.clone(),
        attribution: fields,
    });
    evidence.goal_revision.clone_from(&credit.goal_revision);
    Ok(Some((cell, evidence)))
}
