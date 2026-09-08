//! Gate-family receipt projection for both row families.

use std::collections::BTreeMap;

use super::storage::{
    CITED_RECEIPTS_SEPARATOR, ESCALATION_KEY_PREFIX, ESCALATION_RECEIPT_PREFIX,
    STANDING_POLICY_KEY_PREFIX, STANDING_POLICY_RECEIPT_PREFIX, StoredEscalation,
    StoredStandingPolicy, escalation_key_id, escalation_receipt_id, escalation_row,
    standing_policy_row,
};
use super::types::StandingPolicyStatus;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_ESCALATION_BAND_CEILING, FIELD_ESCALATION_BUDGET_BAND,
    FIELD_ESCALATION_CITED_RECEIPTS, FIELD_ESCALATION_QUESTION, FIELD_ESCALATION_RATIONALE,
    FIELD_ESCALATION_RULING, FIELD_ESCALATION_SCOPE, FIELD_ESCALATION_TRIGGER, FIELD_TASK_REF,
    ReceiptKind, ReceiptQuery, ReceiptRecord, retain_newest_receipt,
};
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a ruled escalation.
#[must_use]
pub fn is_escalation_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(ESCALATION_RECEIPT_PREFIX)
}

/// Whether a receipt is a standing-policy proposal or acceptance.
#[must_use]
pub fn is_standing_policy_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record
            .receipt_id
            .starts_with(STANDING_POLICY_RECEIPT_PREFIX)
}

/// Projects both escalation families as `Gate` receipts.
///
/// Registered in `receipt::collect_receipt_records` beside the gate-decision
/// and ramp projectors, and opens its own read txn as they do.
///
/// Both walks are EXHAUSTIVE, which is forced by the keyspace: these keys are
/// scope-major, so a bounded PREFIX of key order is not a bounded SUFFIX of
/// time order. A scan cap here would let one high-sorting scope's history hide
/// every recent decision made under a lower-sorting one — while
/// [`escalation_stats`] (which walks one scope's range, uncapped) kept counting
/// rows the receipt query could no longer return, breaking the
/// rebuild-from-receipts identity. What is bounded is the RESULT, not the walk:
/// the newest `query.limit` records, kept by
/// [`crate::receipt::retain_newest_receipt`] under the same order the query's
/// final sort uses, exactly as `receipt::gate_receipts` does with its pages.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub(crate) fn escalation_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, ESCALATION_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        retain_projected(
            query,
            &mut out,
            escalation_receipt_record(&escalation_key_id(&key)?, &escalation_row(&raw)?),
        );
    }
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, STANDING_POLICY_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        for record in standing_policy_receipt_records(&standing_policy_row(&raw)?) {
            retain_projected(query, &mut out, record);
        }
    }
    Ok(out)
}

/// Keeps one projected record if the query wants it, newest-first bounded.
///
/// One buffer serves both families: the caller's answer is the newest `limit`
/// receipts across every projector, so the newest `limit` across both of these
/// is exactly what cannot be dropped without changing it.
///
/// A `job_ref` query stays exhaustive, as `receipt::gate_receipts` does and for
/// its reason: that join runs after collection, so a record dropped here could
/// not be found again.
fn retain_projected(query: &ReceiptQuery, out: &mut Vec<ReceiptRecord>, record: ReceiptRecord) {
    if !query.matches(&record) {
        return;
    }
    if query.job_ref.is_some() {
        out.push(record);
    } else {
        retain_newest_receipt(out, record, query.limit);
    }
}

fn escalation_receipt_record(id: &EntityId, row: &StoredEscalation) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_TASK_REF.to_owned(), row.task_ref.clone()),
        (FIELD_ESCALATION_SCOPE.to_owned(), row.scope.clone()),
        (FIELD_ESCALATION_TRIGGER.to_owned(), row.trigger.clone()),
        (FIELD_ESCALATION_RULING.to_owned(), row.ruling.clone()),
        (FIELD_ESCALATION_QUESTION.to_owned(), row.question.clone()),
        (FIELD_ESCALATION_RATIONALE.to_owned(), row.rationale.clone()),
    ]);
    insert_delta_field(&mut fields, row.delta.as_deref());
    if let Some(band) = row.budget_band {
        fields.insert(FIELD_ESCALATION_BUDGET_BAND.to_owned(), band.to_string());
    }
    ReceiptRecord {
        receipt_id: escalation_receipt_id(id),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: None,
        on_behalf_of: None,
        outcome: row.ruling.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!(
            "edit_distance.escalation.{}.{}",
            row.trigger, row.ruling
        )],
        fields,
    }
}

/// The proposal receipt, plus the acceptance receipt once the owner tapped.
///
/// Two records rather than one that changes: the offer and the acceptance are
/// separate acts, and a projection that rewrote the first as the second would
/// lose the fact that a proposal was ever made.
fn standing_policy_receipt_records(row: &StoredStandingPolicy) -> Vec<ReceiptRecord> {
    let mut records = vec![standing_policy_receipt_record(
        row,
        StandingPolicyStatus::Proposed,
        row.proposed_at,
    )];
    if let Some(accepted_at) = row.accepted_at {
        records.push(standing_policy_receipt_record(
            row,
            StandingPolicyStatus::Accepted,
            accepted_at,
        ));
    }
    records
}

fn standing_policy_receipt_record(
    row: &StoredStandingPolicy,
    status: StandingPolicyStatus,
    at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_ESCALATION_SCOPE.to_owned(), row.scope.clone()),
        (FIELD_ESCALATION_TRIGGER.to_owned(), row.trigger.clone()),
        (FIELD_ESCALATION_RULING.to_owned(), row.ruling.clone()),
        (
            FIELD_ESCALATION_CITED_RECEIPTS.to_owned(),
            row.cited_receipts.join(CITED_RECEIPTS_SEPARATOR),
        ),
    ]);
    insert_delta_field(&mut fields, row.delta.as_deref());
    if let Some(ceiling) = row.band_ceiling {
        fields.insert(
            FIELD_ESCALATION_BAND_CEILING.to_owned(),
            ceiling.to_string(),
        );
    }
    ReceiptRecord {
        receipt_id: format!(
            "{STANDING_POLICY_RECEIPT_PREFIX}{}.{}",
            row.row_ref,
            status.as_str()
        ),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: at,
        actor: None,
        on_behalf_of: None,
        outcome: status.as_str().to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!(
            "edit_distance.escalation.standing.{}.{}",
            row.trigger,
            status.as_str()
        )],
        fields,
    }
}

/// Stamps a stored Δ into ED-01's reserved slot, in the same hex spelling
/// `delta::attach_amendment_deltas` writes — one delta language, down to the
/// field key.
fn insert_delta_field(fields: &mut BTreeMap<String, String>, delta: Option<&[u8]>) {
    if let Some(bytes) = delta {
        fields.insert(FIELD_AMENDMENT_DELTA.to_owned(), bytes_to_hex_lower(bytes));
    }
}
