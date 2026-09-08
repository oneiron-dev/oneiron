//! Gate-family receipt projection, discriminators, and receipt record builders.

use super::storage::{
    RAMP_DEMOTION_KEY_PREFIX, RAMP_DEMOTION_OUTCOME, RAMP_DEMOTION_RECEIPT_PREFIX,
    RAMP_DEMOTION_ROW_LABEL, RAMP_OUTCOME_KEY_PREFIX, RAMP_OUTCOME_RECEIPT_PREFIX,
    RAMP_OUTCOME_ROW_LABEL, StoredDemotion, StoredRampOutcome, decode_ramp_row, ramp_row_key_id,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::vault::Vault;

/// Whether a receipt is a ramp self-demotion — the discriminator inside the
/// `Gate` family, since demotions and gate decisions share a kind but not a
/// store.
#[must_use]
pub fn is_ramp_demotion_receipt(record: &ReceiptRecord) -> bool {
    is_ramp_receipt(record, RAMP_DEMOTION_RECEIPT_PREFIX)
}

/// Whether a receipt is a ruling recorded through the ramp door — the witness
/// behind a streak that has no identity-topology event of its own.
#[must_use]
pub fn is_ramp_outcome_receipt(record: &ReceiptRecord) -> bool {
    is_ramp_receipt(record, RAMP_OUTCOME_RECEIPT_PREFIX)
}

fn is_ramp_receipt(record: &ReceiptRecord, prefix: &str) -> bool {
    record.receipt_kind == ReceiptKind::Gate && record.receipt_id.starts_with(prefix)
}

/// Projects this module's two append-only logs as `Gate` receipts. Registered
/// beside `gate_receipts` in `receipt::collect_receipt_records`.
pub(crate) fn ramp_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_OUTCOME_KEY_PREFIX)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, raw) = entry?;
        let row: StoredRampOutcome = decode_ramp_row(&raw, RAMP_OUTCOME_ROW_LABEL)?;
        let id = ramp_row_key_id(RAMP_OUTCOME_KEY_PREFIX, &key, RAMP_OUTCOME_ROW_LABEL)?;
        let receipt = door_outcome_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, raw) = entry?;
        let row: StoredDemotion = decode_ramp_row(&raw, RAMP_DEMOTION_ROW_LABEL)?;
        let id = ramp_row_key_id(RAMP_DEMOTION_KEY_PREFIX, &key, RAMP_DEMOTION_ROW_LABEL)?;
        let receipt = demotion_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    // ED-05's answered offers are the third family on this registration rather
    // than a fourth projector in `receipt::collect_receipt_records`: they are
    // the same ramp, the same `Gate` kind, and — sharing this read txn — they
    // cost no second, nested transaction.
    out.extend(crate::edit_distance::graduation::answer_receipts_in_txn(
        &vault.store,
        &rtxn,
        query,
    )?);
    Ok(out)
}

/// The scope tuple every ramp receipt names, in the SAME field keys the
/// proposal-outcome receipts use — one spelling, so the two families join.
fn scope_receipt_fields(
    op_kind: &str,
    target_class: &str,
    actor: &str,
) -> std::collections::BTreeMap<String, String> {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(crate::receipt::FIELD_OP_KIND.to_owned(), op_kind.to_owned());
    fields.insert(
        crate::receipt::FIELD_TARGET_CLASS.to_owned(),
        target_class.to_owned(),
    );
    fields.insert(
        crate::receipt::FIELD_SCOPE_ACTOR.to_owned(),
        actor.to_owned(),
    );
    fields
}

fn demotion_receipt_record(id: &EntityId, row: &StoredDemotion) -> ReceiptRecord {
    let mut fields = scope_receipt_fields(&row.op_kind, &row.target_class, &row.actor);
    fields.insert(
        crate::receipt::FIELD_DEMOTION_REASON.to_owned(),
        row.reason.clone(),
    );
    if let Some(grant_ref) = row.grant_ref.as_ref() {
        fields.insert(
            crate::receipt::FIELD_GRANT_REF.to_owned(),
            grant_ref.clone(),
        );
    }

    ReceiptRecord {
        receipt_id: format!("{RAMP_DEMOTION_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: RAMP_DEMOTION_OUTCOME.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.ramp.demoted.{}", row.reason)],
        fields,
    }
}

fn door_outcome_receipt_record(id: &EntityId, row: &StoredRampOutcome) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: format!("{RAMP_OUTCOME_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: row.outcome.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.ramp.outcome.{}", row.outcome)],
        fields: scope_receipt_fields(&row.op_kind, &row.target_class, &row.actor),
    }
}
