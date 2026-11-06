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
//! lane's own outcomes: the scan covers the arm the attempt's stamp names
//! under every redirect-equivalent subject (FIX 11673), and the amendment's
//! share reads across every arm (FIX 11674), so a callable invoked under
//! other executors still flips on its invoker arms' share — one share per
//! attempt, charged on each arm.

use std::collections::BTreeMap;

use crate::Vault;
use crate::claim::learning_evidence::EVIDENCE;
use crate::claim::learning_evidence::EvidenceRow;
use crate::claim::learning_evidence::EvidenceSource;
use crate::claim::learning_evidence::LearningEvidence;
use crate::claim::learning_evidence::Observation;
use crate::claim::learning_predicate::LearningPredicate;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::LearningCell;
use crate::learning::evidence::cells_for_subject_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::skill_attribution::{
    LateCreditReceipt, StandingCreditObservation, late_credit_receipt_in_txn,
    standing_credit_observation_in_txn,
};

/// One anchored pack-outcome observation held in a reliability cell,
/// with the subject holding it and the attempt its stored context names,
/// or its sealed credit names for a context-free row (FIX 11675).
pub(super) struct AnchoredRow {
    pub(super) cell: LearningCell,
    pub(super) subject: EntityId,
    pub(super) receipt: String,
    pub(super) attempt: String,
    pub(super) row: EvidenceRow,
}

/// Every anchored pack-outcome observation in `subjects`' reliability
/// cells for `executor`: evidence rows carrying their pack outcome
/// context, each stamped with the subject holding it. A row whose context
/// an erase cleared (FIX 8988) is recovered through its sealed credit
/// receipt's key when the kept receipt, anchor and cell axis all validate;
/// no context is reconstructed, and a missing credit or any mismatch leaves
/// the row out, frozen as it stands (FIX 11675).
///
/// # Errors
///
/// Storage errors.
pub(super) fn anchored_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subjects: &[EntityId],
    executor: &str,
) -> Result<Vec<AnchoredRow>> {
    let mut rows = Vec::new();
    for subject in subjects {
        for held in cells_for_subject_in_txn(vault, txn, subject)? {
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
                    // FIX 11675: exact-credit recovery for a context-free row.
                    // The native row sits under its sealed credit receipt's
                    // key; validate the kept receipt, anchor and cell axis and
                    // read the attempt off the credit. Missing credit or any
                    // mismatch (including a cell without axis) skips the row.
                    let Some(credit) = late_credit_receipt_in_txn(vault, txn, &receipt)? else {
                        continue;
                    };
                    if credit.receipt_id != receipt
                        || credit.anchor != row.anchor
                        || held.cell.axis.as_deref() != Some(credit.axis.as_str())
                    {
                        continue;
                    }
                    rows.push(AnchoredRow {
                        cell: held.cell.clone(),
                        subject: *subject,
                        receipt,
                        attempt: credit.attempt_receipt.clone(),
                        row,
                    });
                    continue;
                };
                rows.push(AnchoredRow {
                    cell: held.cell.clone(),
                    subject: *subject,
                    receipt,
                    attempt: context.attempt_receipt.clone(),
                    row,
                });
            }
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
/// it stands rather than guessed at — except a context-free row recovered
/// through its sealed credit still reads the latest retained masses, which
/// need no attribution. Unknown latest mass or no surviving subject mass
/// leaves it frozen and never newly withdraws (FIX 11675). Either restatement
/// keeps the stored row's receipt key, time, anchor, judge, goal revision and pack context;
/// only the observation and its weight ever move.
///
/// # Errors
///
/// Storage errors.
pub(super) fn effective_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    held: &AnchoredRow,
    amended: &BTreeMap<String, f32>,
) -> Result<AnchoredEffect> {
    let row = &held.row;
    if let Some(share) = amended.get(&held.attempt) {
        if row.pack_attribution.is_none() {
            let Some(credit) = late_credit_receipt_in_txn(vault, txn, &held.receipt)? else {
                return Ok(AnchoredEffect::Stand);
            };
            if matches!(
                standing_credit_observation_in_txn(vault, txn, &credit, &held.subject)?,
                StandingCreditObservation::Unknown
            ) {
                return Ok(AnchoredEffect::Stand);
            }
        }
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
    if credit.attribution.is_none() && row.pack_attribution.is_some() {
        return Ok(AnchoredEffect::Stand);
    }
    match standing_credit_observation_in_txn(vault, txn, &credit, &held.subject)? {
        StandingCreditObservation::Credited(success, weight) => {
            let evidence = restated(held, success, weight);
            Ok(if matches_row(row, &evidence) {
                AnchoredEffect::Stand
            } else {
                AnchoredEffect::Record(evidence)
            })
        }
        // Failed direct credit moves to nothing only after its seating
        // judgments are explicitly displaced. An unrelated failed credit
        // is still not this leaf's row to judge.
        StandingCreditObservation::Uncredited
            if row.pack_attribution.is_some()
                && (credit.succeeded || credit.direct_subjects.contains(&Some(held.subject))) =>
        {
            Ok(AnchoredEffect::Withdraw)
        }
        StandingCreditObservation::Unknown | StandingCreditObservation::Uncredited => {
            Ok(AnchoredEffect::Stand)
        }
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
/// `None` when no sealed credit for `attempt` names `skill` on this arm, no
/// sealed credit matches the attempt's axis, or its attribution is gone. The
/// receipt key is the credit's id, so re-minting
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
        // The sealed lists or the latest adjustment's effective subjects
        // (REVIEW-4322 P1): a subject a later adjustment adds still mints its
        // amendment loss here.
        let mut names = credit.direct_subjects.contains(&Some(*skill))
            || credit
                .shares
                .iter()
                .any(|share| share.subject == Some(*skill));
        if !names {
            names = crate::skill_attribution::effective_credit_subjects_in_txn(
                &vault.store,
                txn,
                &credit,
            )?
            .is_some_and(|subjects| subjects.contains(skill));
        }
        if !names {
            continue;
        }
        candidates.push(credit);
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    let axis = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
        .and_then(|receipt| receipt.fields.get("axis").cloned())
        .unwrap_or_else(|| crate::skill_reliability::SKILL_OUTCOME_AXIS.to_owned());
    candidates.retain(|candidate| candidate.axis == axis);
    let Some(credit) = candidates.into_iter().next() else {
        return Ok(None);
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
