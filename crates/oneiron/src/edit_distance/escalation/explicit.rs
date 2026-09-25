//! Explicit authenticated rulings, committed with the operation they release.
//!
//! Unlike learned graduation, an explicit remember gesture needs no N-ruling
//! proposal. It uses the same ledger, standing-policy schema and cap comparison.

use super::storage::{
    ESCALATION_ROW_LABEL, ROW_VERSION, STANDING_POLICY_ROW_LABEL, StoredEscalation,
    StoredStandingPolicy, encode_row, escalation_key, escalation_receipt_id, normalized_scope,
    ruling_parts, standing_policy_key,
};
use super::{EscalationReceipt, EscalationRuling, EscalationTrigger};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub(crate) fn record_explicit_ruling_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    receipt: EscalationReceipt,
    remember: bool,
    at: u64,
) -> Result<()> {
    if receipt.budget_band.is_some() && receipt.trigger != EscalationTrigger::Budget {
        return Err(Error::InvalidConfig(
            "only budget rulings carry a magnitude".into(),
        ));
    }
    if remember
        && (receipt.trigger != EscalationTrigger::Budget
            || receipt.budget_band.is_none()
            || receipt.ruling != EscalationRuling::Approve)
    {
        return Err(Error::InvalidConfig(
            "remember requires a bounded approval".into(),
        ));
    }
    let scope = normalized_scope(&receipt.scope)?.to_owned();
    let (ruling, delta) = ruling_parts(&receipt.ruling)?;
    let id = EntityId::now();
    let row = StoredEscalation {
        v: ROW_VERSION,
        task_ref: receipt.task_ref.to_hex(),
        scope: scope.clone(),
        trigger: receipt.trigger.as_str().to_owned(),
        question: receipt.question,
        ruling: ruling.clone(),
        delta: delta.clone(),
        rationale: format!(
            "{};owner={};authentication={}",
            receipt.rationale,
            owner.principal_ref(),
            owner.decision_id().to_hex()
        ),
        budget_band: receipt.budget_band,
        at,
    };
    vault.store.vault_meta.put(
        txn,
        &escalation_key(&scope, &id),
        &encode_row(&row, ESCALATION_ROW_LABEL)?,
    )?;
    if remember {
        let policy = StoredStandingPolicy {
            v: ROW_VERSION,
            row_ref: EntityId::now().to_hex(),
            scope: scope.clone(),
            trigger: receipt.trigger.as_str().to_owned(),
            ruling,
            delta,
            band_ceiling: receipt.budget_band,
            cited_receipts: vec![escalation_receipt_id(&id)],
            proposed_at: at,
            accepted_at: Some(at),
        };
        vault.store.vault_meta.put(
            txn,
            &standing_policy_key(&scope, receipt.trigger),
            &encode_row(&policy, STANDING_POLICY_ROW_LABEL)?,
        )?;
    }
    Ok(())
}
