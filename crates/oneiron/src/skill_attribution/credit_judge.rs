//! An existing anchored credit's late judge provenance; its score stays sealed.

use std::collections::BTreeSet;

use crate::claim::learning_evidence::EVIDENCE;
use crate::entity_id::EntityId;
use crate::learning::LearningPredicate;
use crate::receipt::PackAttributionFields;
use crate::{Result, Vault};

use super::late_credit::LateCreditReceipt;

/// Capture only: a failed refresh leaves both the evidence and its heads alone.
pub(super) fn capture_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    credit: &LateCreditReceipt,
    fields: &PackAttributionFields,
    now: u64,
) {
    let Some(judge) = fields.judge.as_deref() else {
        return;
    };
    if credit
        .attribution
        .as_ref()
        .is_none_or(|held| held.judge.is_some())
    {
        return;
    }
    if let Err(error) = super::derivation_witness::in_savepoint(&vault.store, txn, |txn| {
        refresh_in_txn(vault, txn, credit, judge, now)
    }) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            "an existing credit's late judge was not joined; its evidence stays unchanged"
        );
    }
}

fn refresh_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    credit: &LateCreditReceipt,
    judge: &str,
    now: u64,
) -> Result<()> {
    let mut subjects: BTreeSet<EntityId> =
        credit.direct_subjects.iter().flatten().copied().collect();
    subjects.extend(credit.shares.iter().filter_map(|share| share.subject));
    // An amendment may retain a loss after its subject left the current mass.
    for (_, adjustment) in super::credit_join::chain_in_txn(&vault.store, txn, &credit.receipt_id)?
    {
        subjects.extend(adjustment.direct_subjects.into_iter().flatten());
        subjects.extend(
            adjustment
                .shares
                .into_iter()
                .filter_map(|share| share.subject),
        );
    }
    if let Some(receipt) =
        crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &credit.attempt_receipt)?
        && let Some(person) = receipt
            .on_behalf_of
            .as_deref()
            .or(receipt.actor.as_deref())
            .and_then(|actor| EntityId::from_hex(actor).ok())
    {
        subjects.insert(person);
    }
    for subject in subjects {
        for cell in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, &subject)? {
            if cell.cell.predicate != LearningPredicate::Reliability {
                continue;
            }
            let digest = cell.cell.digest();
            let key = (digest, credit.receipt_id.clone());
            let Some(mut row) = EVIDENCE.get(&vault.store, txn, &key)? else {
                continue;
            };
            if row.judge.is_some() {
                continue;
            }
            let Some(pack) = row.pack_attribution.as_mut() else {
                continue;
            };
            if pack.attempt_receipt != credit.attempt_receipt
                || pack.outcome_receipt != credit.outcome_receipt
                || pack.attribution.judge.is_some()
            {
                continue;
            }
            row.judge = Some(judge.to_owned());
            row.on_judge_model = judge == pack.attribution.executor;
            pack.attribution.judge = row.judge.clone();
            EVIDENCE.put(&vault.store, txn, &key, &row)?;
            crate::learning::project::project_cell_in_txn(vault, txn, &digest, now)?;
        }
    }
    Ok(())
}
