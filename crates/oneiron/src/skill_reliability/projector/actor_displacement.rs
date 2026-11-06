//! Reconcile only native failed actor credit after explicit judge displacement.

use super::*;

pub(crate) fn reconcile_displaced_actor_credit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    attempt: &str,
    at: u64,
) -> Result<()> {
    let executors: BTreeSet<_> = cells_for_subject_in_txn(vault, txn, actor)?
        .into_iter()
        .filter(|row| row.cell.predicate == crate::learning::LearningPredicate::Reliability)
        .filter_map(|row| row.cell.executor)
        .collect();
    let amended = amended_receipt_shares_in_txn(vault, txn, actor)?;
    for executor in executors {
        for held in anchored_rows_in_txn(vault, txn, &[*actor], &executor)? {
            if held.attempt != attempt {
                continue;
            }
            let Some(credit) =
                crate::skill_attribution::late_credit_receipt_in_txn(vault, txn, &held.receipt)?
            else {
                continue;
            };
            let Some(fields) = credit.attribution.as_ref() else {
                continue;
            };
            if credit.succeeded
                || !credit.direct_subjects.contains(&Some(*actor))
                || credit.receipt_id != held.receipt
                || credit.attempt_receipt != held.attempt
                || held.cell.executor.as_deref() != Some(fields.executor.as_str())
                || held.cell.type_ref.as_ref() != Some(&fields.type_ref)
                || held.cell.axis.as_deref() != Some(credit.axis.as_str())
                || held.cell.project != fields.project
                || !context_matches(&held.row, &credit)
                || !matches!(held.row.observation, Observation::Success(false))
                || !matches!(
                    effective_evidence_in_txn(vault, txn, &held, &amended)?,
                    AnchoredEffect::Withdraw
                )
            {
                continue;
            }
            let person_cell =
                crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &held.attempt)?
                    .and_then(|attempt| {
                        attempt
                            .on_behalf_of
                            .as_deref()
                            .or(attempt.actor.as_deref())
                            .and_then(|person| EntityId::from_hex(person).ok())
                    })
                    .and_then(|person| anchored_person_cell(&held.cell, person));
            let person_row = match person_cell.as_ref() {
                Some(cell) => EVIDENCE
                    .get(&vault.store, txn, &(cell.digest(), held.receipt.clone()))?
                    .filter(|row| context_matches(row, &credit)),
                None => None,
            };
            if person_cell
                .as_ref()
                .is_none_or(|cell| cell.digest() != held.cell.digest() || person_row.is_none())
            {
                crate::learning::evidence::withdraw_evidence_in_txn(
                    vault,
                    txn,
                    &held.cell,
                    &held.receipt,
                    at,
                )?;
            }
            let (Some(person_cell), Some(row)) = (person_cell, person_row) else {
                continue;
            };
            let observation = match recomputed_person_observation(
                vault,
                txn,
                &credit,
                &held.attempt,
                *actor,
                Some(actor),
            )? {
                StandingCreditObservation::Credited(success, weight) => Some((success, weight)),
                StandingCreditObservation::Uncredited => None,
                StandingCreditObservation::Unknown => continue,
            };
            if let Some(observation) = observation {
                let mut evidence = LearningEvidence::anchored(
                    held.receipt.clone(),
                    row.at,
                    row.anchor,
                    Observation::Success(observation.0),
                );
                evidence.weight = observation.1;
                evidence.judge = row.judge;
                evidence.on_judge_model = row.on_judge_model;
                evidence.outcome_label = row.outcome_label;
                evidence.pack_attribution = row.pack_attribution;
                evidence.goal_revision = row.goal_revision;
                evidence.measurement_version = row.measurement_version;
                record_recomputed_person_evidence_in_txn(
                    vault,
                    txn,
                    &person_cell,
                    &evidence,
                    observation,
                    at,
                    &mut BTreeSet::new(),
                )?;
            } else {
                crate::learning::evidence::withdraw_evidence_in_txn(
                    vault,
                    txn,
                    &person_cell,
                    &held.receipt,
                    at,
                )?;
            }
        }
    }
    Ok(())
}

fn context_matches(row: &EvidenceRow, credit: &LateCreditReceipt) -> bool {
    row.pack_attribution.as_ref().is_some_and(|context| {
        context.attempt_receipt == credit.attempt_receipt
            && context.outcome_receipt == credit.outcome_receipt
            && credit.attribution.as_ref() == Some(&context.attribution)
    })
}
