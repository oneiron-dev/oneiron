//! The selected local A9 slice of a courtesy Redact answer.
//! Owner/copy admission and every edit/receipt share the answer's writer.
//! No values, allegations or removed bytes enter the receipt.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CooperativeDeletionAnswer, CooperativeDeletionDispositionKind, CooperativeLocalRedaction,
    IncomingCooperativeDeletion,
};
use crate::{EntityId, Result, Vault};

pub(super) fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pact: &[u8; 32],
    filed: &IncomingCooperativeDeletion,
    actor: EntityId,
    answer: &CooperativeDeletionAnswer,
    now: u64,
) -> Result<(Vec<CooperativeLocalRedaction>, Vec<EntityId>)> {
    if answer.kind != CooperativeDeletionDispositionKind::Redact {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut selections = BTreeMap::<EntityId, BTreeSet<String>>::new();
    for selected in &answer.redact {
        selections
            .entry(selected.record)
            .or_default()
            .extend(selected.value_fields.iter().cloned());
    }
    let records: Vec<_> = selections.keys().copied().collect();
    let (covered, excluded) =
        super::answer::present_copies_for_ask(vault, txn, pact, filed, &records)?;
    let mut receipts = Vec::with_capacity(covered.len());
    for id in covered {
        let fields: Vec<_> = selections
            .remove(&id)
            .expect("covered selection")
            .into_iter()
            .collect();
        let result = crate::vault::entity_revision::redact_claim_value_fields_in_txn(
            vault, txn, id, &fields, actor,
        )?;
        receipts.push(CooperativeLocalRedaction {
            applied_by: actor,
            applied_at: now,
            result,
        });
    }
    Ok((receipts, excluded))
}
