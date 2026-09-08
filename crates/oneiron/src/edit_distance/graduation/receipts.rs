//! Receipt projection for graduation answers.

use super::answers::{StoredAnswer, answer_key_id};
use super::{ANSWER_KEY_PREFIX, ANSWER_RECEIPT_PREFIX, ANSWER_ROW_LABEL, ROW_VERSION, decode_row};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
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

/// Names the first key past the answer-log family, so the reverse walk has the
/// explicit half-open range `OverlayDb` needs (it exposes no reverse prefix
/// iterator). The prefix is an ASCII literal, so bumping its final byte is the
/// exclusive bound.
fn answer_key_range_end() -> Vec<u8> {
    let mut end = ANSWER_KEY_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Projects the answer log as `Gate` receipts, on the caller's read txn.
///
/// Called from `consent_graduation::ramp_receipts`, which is what is registered
/// in `receipt::collect_receipt_records`: the ramp's receipt families share one
/// registration and one transaction rather than opening a second, nested one.
///
/// Walks the family NEWEST-FIRST under [`crate::receipt::MAX_RECEIPT_QUERY_SCAN`],
/// as `receipt::attempt_pack_receipts` does and for the same reason. Direction
/// is the whole point of the cap: these rows never drain — [`unpin_scope`]
/// appends unconditionally and the log is the state — so an oldest-first cap
/// would permanently hide the owner's RECENT decisions behind their oldest
/// ones, which is the opposite of what any receipt query wants. The key is
/// scope-major and time-minor, so this is newest-first within each scope, with
/// the bound spent on the scopes at the far end of the digest order.
///
/// Above the cap the answer is a bounded prefix of the family rather than the
/// family, which [`note_answer_scan_capped`] says out loud instead of
/// truncating in silence.
pub(crate) fn answer_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let end = answer_key_range_end();
    let bounds = (
        std::ops::Bound::Included(ANSWER_KEY_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut out = Vec::new();
    // One row PAST the cap is reached and never decoded: it is what separates a
    // log holding exactly the cap from one the cap truncated.
    for (scanned, entry) in store
        .vault_meta
        .rev_range(txn, &bounds)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            note_answer_scan_capped();
            break;
        }
        let (key, raw) = entry?;
        let row: StoredAnswer = decode_row(&raw, ANSWER_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(ANSWER_ROW_LABEL));
        }
        let receipt = answer_receipt_record(&answer_key_id(&key)?, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    Ok(out)
}

/// Surfaces an answer-log scan that stopped at the work cap.
///
/// The discarded remainder is unbounded by construction, so it is never
/// counted — the signal is that the cap FIRED, which is the fact an operator
/// (or a test) needs to know the query answered from a prefix.
fn note_answer_scan_capped() {
    tracing::warn!(
        scan_cap = crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        "graduation answer scan hit the receipt-family work cap; older rows were not projected"
    );
    #[cfg(test)]
    ANSWER_SCAN_CAPPED.with(|fired| fired.set(fired.get() + 1));
}

#[cfg(test)]
thread_local! {
    static ANSWER_SCAN_CAPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn answer_scan_capped() -> usize {
    ANSWER_SCAN_CAPPED.get()
}

#[cfg(test)]
pub(super) fn reset_answer_scan_capped() {
    ANSWER_SCAN_CAPPED.set(0);
}

fn answer_receipt_record(id: &EntityId, row: &StoredAnswer) -> ReceiptRecord {
    let fields = std::collections::BTreeMap::from([
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
