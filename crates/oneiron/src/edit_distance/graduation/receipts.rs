//! Receipt projection for graduation answers.

use super::answers::StoredAnswer;
use super::{ANSWER, ANSWER_RECEIPT_PREFIX};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

// ---------------------------------------------------------------------------
// Receipts (third projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is an answered graduation offer — the discriminator
/// inside the `Gate` family, beside MS-06's demotion and outcome prefixes.
#[must_use]
pub fn is_graduation_answer_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate && record.receipt_id.starts_with(ANSWER_RECEIPT_PREFIX)
}

/// Projects the answer log as `Gate` receipts, on the caller's read txn.
///
/// Called from `consent_graduation::ramp_receipts`, which is what is registered
/// in `receipt::collect_receipt_records`: the ramp's receipt families share one
/// registration and one transaction rather than opening a second, nested one.
///
/// Walks the whole family, newest-first within each scope: these rows never
/// drain ([`unpin_scope`] appends unconditionally and the log is the state),
/// and the key is scope-major, so any prefix of the walk could hide the
/// owner's newest decision in another scope. Past the family's threshold row
/// the walk raises one check and reads on; the query's limit applies after
/// the caller's global sort.
pub(crate) fn answer_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut rows = ScanCount::start(store, txn, EngineScan::AnswerReceiptRows, &[])?;
    let mut out = Vec::new();
    for entry in ANSWER.iter_rev_from(store, txn, &[])? {
        let ((_, id), row) = entry?;
        rows.row();
        let receipt = answer_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    rows.defer(store);
    Ok(out)
}

fn answer_receipt_record(id: &EntityId, row: &StoredAnswer) -> ReceiptRecord {
    let mut fields = std::collections::BTreeMap::from([
        (
            crate::receipt::FIELD_OP_KIND.to_owned(),
            row.op_kind.clone(),
        ),
        (
            crate::receipt::FIELD_TARGET_CLASS.to_owned(),
            row.target_class.clone(),
        ),
        (
            crate::receipt::FIELD_SCOPE_ACTOR.to_owned(),
            row.actor.clone(),
        ),
    ]);
    if let Some(answerer) = &row.answerer {
        fields.insert("answerer".to_owned(), answerer.clone());
    }
    if let Some(decision_ref) = &row.decision_ref {
        fields.insert("decision_ref".to_owned(), decision_ref.clone());
    }

    ReceiptRecord {
        receipt_id: format!("{ANSWER_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: row.answer.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.graduation.answer.{}", row.answer)],
        fields,
    }
}
